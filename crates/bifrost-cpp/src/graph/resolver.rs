use crate::call_match::{
    CppArgType, cpp_signature_param_types, cpp_split_top_level_commas, normalize_cpp_type_name,
};
use crate::compile_context::CppCompileContext;
#[cfg(test)]
use crate::declarations::cpp_displaced_preprocessor_terminator;
use crate::declarations::{
    CppComparableNode, CppComparableParameter, CppComparableSlot, CppRecoveredExportClassIndex,
    cpp_callable_identity_suffix, cpp_comparable_parameter_shapes, cpp_declarator_adds_indirection,
    cpp_displaced_preprocessor_boundary, cpp_export_macro_token, cpp_field_declaration_linkage,
    cpp_function_declarator_at, cpp_template_term, node_text, normalize_cpp_whitespace,
    recovered_class_body_at,
};
use crate::graph::CppGraphSource;
use crate::graph::extractor::ScanCtx;
use crate::graph::syntax::object_macro_replacement_type_references;
use crate::graph_support::CppSource;
use crate::imports::{
    IncludeTargetIndex, include_paths as cpp_include_paths, resolve_include_targets_with_index,
};
use brokk_bifrost_core::analyzer::fq_name::{FqName, SegmentKind, segment_interner};
use brokk_bifrost_core::analyzer::model::{
    CallableArity, CodeUnitType, CppFieldLinkage, CppTemplateExpression, CppTemplateMetadata,
    CppTemplateParameterMetadata, CppTemplateTerm, Language, LanguageDialect, StructuredTypeName,
};
use brokk_bifrost_core::analyzer::pool_memo::PoolSafeMemo;
use brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree;
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_core::analyzer::tree_walk::{ParentIndex, node_for_exact_range};
use brokk_bifrost_core::analyzer::usages::common::same_node;
use brokk_bifrost_core::analyzer::usages::local_inference::LocalInferenceEngine;
use brokk_bifrost_core::analyzer::{CodeUnit, ProjectFile, Range};
use brokk_bifrost_core::cancellation::CancellationToken;
use brokk_bifrost_core::hash::{HashMap, HashSet};
use std::borrow::Cow;
#[cfg(any(test, feature = "test-support"))]
use std::cell::Cell;
use std::cell::OnceCell;
use std::cmp::Ordering as CmpOrdering;
use std::collections::BTreeSet;
use std::hash::Hash;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant};
use tree_sitter::{Node, Parser, Tree};

#[cfg(any(test, feature = "test-support"))]
thread_local! {
    static BOUNDED_VISIBILITY_DECLARATION_READ_COUNT: Cell<usize> = const { Cell::new(0) };
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TargetKind {
    Type,
    Constructor,
    FreeFunction,
    Method,
    GlobalField,
    MemberField,
    Macro,
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

/// Why a name did not reduce to one indexed type declaration.
///
/// The two answers are not interchangeable. `Ambiguous` means the index holds
/// several declarations and the caller must choose; `Unresolvable` means the
/// index holds none, which is a boundary the workspace cannot see past. A
/// `using`/`typedef` alias to a template parameter or to a standard-library
/// type is unresolvable, and reporting it as ambiguity produced an `ambiguous`
/// answer with an empty candidate list (#1828).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TypeCandidateFailure {
    Ambiguous,
    Unresolvable,
}

impl TypeCandidateFailure {
    fn lexical_resolution(self) -> LexicalTypeResolution {
        match self {
            Self::Ambiguous => LexicalTypeResolution::Ambiguous,
            Self::Unresolvable => LexicalTypeResolution::Missing,
        }
    }
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OrdinaryMacroReferenceResolution {
    Resolved(CodeUnit),
    Ambiguous,
    Missing,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecoveredCReferenceRanges {
    Complete(Vec<Range>),
    LimitExceeded,
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
    pub callable_has_definition_body: bool,
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
            let owner_resolution = target_type_owner_resolution(analyzer, target);
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
                cpp_callable_parameter_types(analyzer, target),
            );
            spec.owner_is_forward_declaration = owner_is_forward_declaration;
            spec.callable_has_definition_body =
                callable_target_has_definition_body(analyzer, target);
            return Some(spec);
        }

        if target.is_macro() {
            return Some(Self::new(
                target.clone(),
                TargetKind::Macro,
                None,
                target.identifier().to_string(),
                None,
                None,
            ));
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
            callable_has_definition_body: false,
        }
    }
}

fn callable_target_has_definition_body(analyzer: &CppGraphSource<'_>, target: &CodeUnit) -> bool {
    let Some(cpp) = analyzer.cpp else {
        return false;
    };
    let Some(prepared) = cpp.prepared_syntax(analyzer.token, target.source()) else {
        return false;
    };
    analyzer.ranges(target).into_iter().any(|range| {
        let end = range
            .start_byte
            .saturating_add(1)
            .min(prepared.source().len());
        let mut current = prepared
            .tree()
            .root_node()
            .descendant_for_byte_range(range.start_byte, end);
        while let Some(node) = current {
            match node.kind() {
                "function_definition" => return true,
                "declaration" => return false,
                _ => current = node.parent(),
            }
        }
        false
    })
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
pub type OrdinaryTypeImportCell = Arc<EffectiveUsingIndex>;
pub type MacroEventCell = Arc<OnceLock<Box<[MacroEvent]>>>;
type MacroIncludeProtectionCell = Arc<OnceLock<MacroIncludeProtection>>;
type MacroEnvironmentCheckpointCell = Arc<OnceLock<MacroEnvironmentCheckpoints>>;
type MacroReplacementCache = HashMap<(ProjectFile, usize), Arc<ParsedMacroReplacement>>;
type MacroLocalBindingTemplateCache =
    HashMap<(ProjectFile, usize), Option<Arc<MacroLocalBindingTemplate>>>;
type MacroReplacementBodyCache = HashMap<(ProjectFile, usize), Option<Arc<ParsedReplacementBody>>>;

#[derive(Clone, Default)]
pub struct MacroEnvironment {
    bindings: HashMap<String, MacroBinding>,
    known_undefined_names: HashSet<String>,
    /// Names the translation unit's compile command proves defined (#2011):
    /// the `-D`s that survive command ordering, intersected across every
    /// configuration naming the TU. Seeded once at TU start. An explicit
    /// `#undef` seen later lands in `known_undefined_names` and wins.
    build_proven_defines: HashSet<String>,
    unknown_names: bool,
    applied_pragma_once_files: HashSet<ProjectFile>,
    maybe_applied_pragma_once_files: HashSet<ProjectFile>,
}

/// How many macro events one checkpoint window may cover.
///
/// A request for an environment replays only the events between the nearest
/// earlier checkpoint and its own frontier, so one file's whole scan costs its
/// event count (the checkpoint build) plus this many applications per request,
/// whatever order the requests arrive in. The forward cursor this replaced was
/// optimal for one worker reading one file in byte order and quadratic for the
/// inverse, which asks many workers for positions that move backwards (#1496).
pub const MACRO_ENVIRONMENT_CHECKPOINT_STRIDE: usize = 32;

/// One event prefix of a file whose environment the index keeps.
struct MacroEnvironmentCheckpoint {
    /// How many of the file's events this environment has applied.
    frontier: usize,
    environment: Arc<MacroEnvironment>,
}

/// The replay checkpoints for one file's macro events, ascending by frontier
/// and always starting at frontier zero (the compile-proven defines alone).
///
/// A checkpoint lands every [`MACRO_ENVIRONMENT_CHECKPOINT_STRIDE`] events and
/// directly after every `#include` event, because applying an include event
/// replays the included file's complete event list: keeping one there is what
/// holds that unbounded cost out of every later replay window.
struct MacroEnvironmentCheckpoints {
    checkpoints: Vec<MacroEnvironmentCheckpoint>,
}

impl MacroEnvironmentCheckpoints {
    /// The latest checkpoint at or before `frontier`.
    fn at_or_before(&self, frontier: usize) -> &MacroEnvironmentCheckpoint {
        let index = self
            .checkpoints
            .partition_point(|checkpoint| checkpoint.frontier <= frontier);
        assert!(
            index > 0,
            "a checkpoint vector starts at frontier zero, which precedes every request"
        );
        &self.checkpoints[index - 1]
    }
}

impl MacroEnvironment {
    fn binding(&self, name: &str) -> Option<&MacroBinding> {
        self.bindings.get(name)
    }

    fn may_bind(&self, name: &str) -> bool {
        self.bindings.contains_key(name) || self.unknown_names
    }

    fn insert(&mut self, name: String, binding: MacroBinding) {
        self.known_undefined_names.remove(&name);
        self.bindings.insert(name, binding);
    }

    fn remove(&mut self, name: &str) {
        self.bindings.remove(name);
        self.known_undefined_names.insert(name.to_string());
    }

    fn remove_known_undefined(&mut self, name: &str) {
        self.known_undefined_names.remove(name);
    }

    fn mark_unknown_names(&mut self, source: &ProjectFile, byte: usize) {
        for binding in self.bindings.values_mut() {
            *binding = MacroBinding::uncertain_from(binding, source, byte);
        }
        self.known_undefined_names.clear();
        // An untracked include could `#undef` a command-line define, so the
        // may-hold filter must stop treating the build facts as decisive from
        // here on. The additive proof path keeps its facts: they still hold at
        // the include chain's activation point.
        self.build_proven_defines.clear();
        self.unknown_names = true;
    }

    fn guard_requirements_may_hold(&self, guards: &HashSet<PreprocessorGuard>) -> bool {
        guards.iter().all(|guard| self.guard_may_hold(guard))
    }

    fn guard_may_hold(&self, guard: &PreprocessorGuard) -> bool {
        let Some(expression) = guard.as_boolean_expression() else {
            return true;
        };
        self.boolean_guard_may_hold(&expression)
    }

    fn boolean_guard_may_hold(&self, expression: &BooleanGuardExpression) -> bool {
        match expression {
            BooleanGuardExpression::Defined(name) => !self.known_undefined_names.contains(name),
            BooleanGuardExpression::Undefined(name) => {
                self.bindings
                    .get(name)
                    .is_none_or(|binding| !binding.is_exact())
                    && (!self.build_proven_defines.contains(name)
                        || self.known_undefined_names.contains(name))
            }
            BooleanGuardExpression::Truthy(_) | BooleanGuardExpression::Falsy(_) => true,
            BooleanGuardExpression::Opaque(_)
            | BooleanGuardExpression::NegatedOpaque(_)
            | BooleanGuardExpression::Constant(true) => true,
            BooleanGuardExpression::Constant(false) => false,
            BooleanGuardExpression::All(expressions) => expressions
                .iter()
                .all(|expression| self.boolean_guard_may_hold(expression)),
            BooleanGuardExpression::Any(expressions) => expressions
                .iter()
                .any(|expression| self.boolean_guard_may_hold(expression)),
        }
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
    pub block_scope: bool,
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
type ConditionalIncludeProjectionIndex = HashMap<ProjectFile, Arc<[ConditionalIncludeProjection]>>;
type ConditionalIncludeProjectionCell = Arc<PoolSafeMemo<ConditionalIncludeProjectionIndex>>;
type ConditionalIncludeProjectionCache = HashMap<ProjectFile, ConditionalIncludeProjectionCell>;
type VisibleParserAliasNameSetCell = Arc<OnceLock<HashSet<String>>>;
type IndexedStructuralClassScopeCache = HashMap<(ProjectFile, usize, usize), Option<Vec<String>>>;
type IndexedEnclosingOwnerScopeCache = HashMap<(ProjectFile, usize, usize), Option<Vec<String>>>;

/// One callable declaration's inputs to [`VisibilityIndex::same_logical_callable`],
/// read from its declaration syntax rather than from its persisted signature
/// string: the comparable shape of each parameter, and the trailing identity
/// suffix that shape does not carry.
struct ExtractedComparable {
    shapes: Vec<CppComparableSlot>,
    suffix: String,
}

/// How many alias hops [`VisibilityIndex::same_logical_callable`] follows
/// before giving up on a written type name. A visited set already stops a
/// cycle; this stops an adversarially long chain from costing a lookup per hop.
const MAX_COMPARABLE_ALIAS_HOPS: usize = 32;

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
    /// Proof that the request scope the index was built under is still open.
    /// The index is a per-query object whose lifetime is inside the scope's,
    /// so carrying the token here instead of on ninety method signatures is
    /// the same guarantee for far less plumbing (issue #2414 step 3).
    token: QueryToken<'a>,
    pub visible_by_file: HashMap<ProjectFile, HashSet<CodeUnit>>,
    visible_by_identifier: HashMap<ProjectFile, HashMap<String, Vec<CodeUnit>>>,
    global_field_internal_linkage: HashMap<CodeUnit, bool>,
    visible_source_files_by_root: HashMap<ProjectFile, HashSet<ProjectFile>>,
    alias_cells: Mutex<HashMap<ProjectFile, AliasCell>>,
    visible_parser_alias_name_sets: RwLock<HashMap<ProjectFile, VisibleParserAliasNameSetCell>>,
    ordinary_type_import_cells: Mutex<HashMap<ProjectFile, OrdinaryTypeImportCell>>,
    project_using_index: OnceLock<ProjectUsingIndex>,
    callable_reference_specs:
        Mutex<HashMap<(ProjectFile, LogicalSymbolKey), CallableReferenceSpecCell>>,
    include_activation_cells: Mutex<HashMap<(ProjectFile, ProjectFile), Option<usize>>>,
    compile_proven_guard_cells: Mutex<HashMap<ProjectFile, Arc<HashSet<PreprocessorGuard>>>>,
    conditional_include_projection_cells: Mutex<ConditionalIncludeProjectionCache>,
    #[cfg(any(test, feature = "test-support"))]
    conditional_include_projection_index_build_count: AtomicUsize,
    #[cfg(any(test, feature = "test-support"))]
    conditional_include_projection_state_count: AtomicUsize,
    #[cfg(any(test, feature = "test-support"))]
    conditional_include_target_state_count: AtomicUsize,
    #[cfg(any(test, feature = "test-support"))]
    include_activation_build_count: AtomicUsize,
    #[cfg(any(test, feature = "test-support"))]
    using_donor_activation_count: AtomicUsize,
    #[cfg(any(test, feature = "test-support"))]
    using_namespace_lookup_count: AtomicUsize,
    #[cfg(any(test, feature = "test-support"))]
    using_name_candidate_inspection_count: AtomicUsize,
    #[cfg(any(test, feature = "test-support"))]
    callable_reference_spec_build_count: AtomicUsize,
    #[cfg(any(test, feature = "test-support"))]
    alias_source_parse_counts: Mutex<HashMap<ProjectFile, usize>>,
    #[cfg(any(test, feature = "test-support"))]
    visible_parser_alias_name_set_build_count: AtomicUsize,
    parser_alias_fallback_calls: AtomicUsize,
    parser_alias_fallback_files: AtomicUsize,
    parser_alias_source_parses: AtomicUsize,
    parser_alias_fallback_elapsed_micros: AtomicUsize,
    field_type_facts: Mutex<HashMap<CodeUnit, Option<DeclaredFieldTypeFact>>>,
    structured_alias_targets: Mutex<HashMap<CodeUnit, Option<StructuredAliasTarget>>>,
    callable_comparables: Mutex<HashMap<CodeUnit, Option<Arc<ExtractedComparable>>>>,
    indexed_structural_class_scopes: Mutex<IndexedStructuralClassScopeCache>,
    indexed_enclosing_owner_scopes: Mutex<IndexedEnclosingOwnerScopeCache>,
    precise_parent_cache: Mutex<HashMap<CodeUnit, Option<CodeUnit>>>,
    macro_event_cells: Mutex<HashMap<ProjectFile, MacroEventCell>>,
    pub macro_include_protection_cells: Mutex<HashMap<ProjectFile, MacroIncludeProtectionCell>>,
    // The environment at selected event prefixes of each file, built once and read by every
    // worker. The authoritative differential shares this index across target workers whose
    // frontiers interleave arbitrarily and move backwards, so a forward cursor -- per worker or
    // not -- replayed a file's events once per backward request. Checkpoints answer any position
    // with a binary search and at most one stride of replay, and being immutable they need no
    // per-worker copy (#1496).
    macro_environment_checkpoints: Mutex<HashMap<ProjectFile, MacroEnvironmentCheckpointCell>>,
    macro_replacements: Mutex<MacroReplacementCache>,
    macro_local_binding_templates: Mutex<MacroLocalBindingTemplateCache>,
    macro_replacement_bodies: Mutex<MacroReplacementBodyCache>,
    callable_parameter_macro_arities: Mutex<HashMap<(ProjectFile, String), Option<CallableArity>>>,
    #[cfg(any(test, feature = "test-support"))]
    pub macro_replacement_parse_count: AtomicUsize,
    #[cfg(any(test, feature = "test-support"))]
    pub macro_event_application_count: AtomicUsize,
    /// How many files had their checkpoint vector built. One build per file
    /// per query even when workers race for the same file.
    #[cfg(any(test, feature = "test-support"))]
    pub macro_environment_checkpoint_build_count: AtomicUsize,
    /// How many requests landed off a checkpoint and so had to copy one and
    /// replay the events after it.
    #[cfg(any(test, feature = "test-support"))]
    pub macro_environment_copy_count: AtomicUsize,
    #[cfg(any(test, feature = "test-support"))]
    pub macro_environment_request_count: AtomicUsize,
    cpp_template_metadata: HashMap<CodeUnit, CppTemplateMetadata>,
    cpp_template_families: HashMap<String, Vec<CodeUnit>>,
    #[cfg(any(test, feature = "test-support"))]
    qualified_candidate_inspections: AtomicUsize,
    #[cfg(any(test, feature = "test-support"))]
    target_preserving_type_resolution_count: AtomicUsize,
}

impl Drop for VisibilityIndex<'_> {
    fn drop(&mut self) {
        if std::env::var_os("BIFROST_CPP_VISIBILITY_STATS").is_none() {
            return;
        }
        #[cfg(any(test, feature = "test-support"))]
        eprintln!(
            "BIFROST_CPP_MACRO_STATS requests={} copies={} checkpoint_builds={} applications={}",
            self.macro_environment_request_count.load(Ordering::Relaxed),
            self.macro_environment_copy_count.load(Ordering::Relaxed),
            self.macro_environment_checkpoint_build_count
                .load(Ordering::Relaxed),
            self.macro_event_application_count.load(Ordering::Relaxed),
        );
        let calls = self.parser_alias_fallback_calls.load(Ordering::Relaxed);
        if calls == 0 {
            return;
        }
        eprintln!(
            "BIFROST_CPP_ALIAS_FALLBACK_STATS calls={} files={} source_parses={} elapsed_ms={}",
            calls,
            self.parser_alias_fallback_files.load(Ordering::Relaxed),
            self.parser_alias_source_parses.load(Ordering::Relaxed),
            self.parser_alias_fallback_elapsed_micros
                .load(Ordering::Relaxed)
                / 1_000,
        );
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum PreprocessorGuard {
    Defined(String),
    Undefined(String),
    Boolean(BooleanGuardExpression),
    Expression(String),
    NegatedExpression(String),
    Constant(bool),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum BooleanGuardExpression {
    Defined(String),
    Undefined(String),
    Truthy(String),
    Falsy(String),
    Opaque(String),
    NegatedOpaque(String),
    All(Vec<BooleanGuardExpression>),
    Any(Vec<BooleanGuardExpression>),
    Constant(bool),
}

impl BooleanGuardExpression {
    fn negated(&self) -> Self {
        match self {
            Self::Defined(name) => Self::Undefined(name.clone()),
            Self::Undefined(name) => Self::Defined(name.clone()),
            Self::Truthy(name) => Self::Falsy(name.clone()),
            Self::Falsy(name) => Self::Truthy(name.clone()),
            Self::Opaque(expression) => Self::NegatedOpaque(expression.clone()),
            Self::NegatedOpaque(expression) => Self::Opaque(expression.clone()),
            Self::All(expressions) => Self::any(expressions.iter().map(Self::negated)),
            Self::Any(expressions) => Self::all(expressions.iter().map(Self::negated)),
            Self::Constant(value) => Self::Constant(!value),
        }
    }

    fn all(expressions: impl IntoIterator<Item = Self>) -> Self {
        Self::normalized(expressions, true)
    }

    fn any(expressions: impl IntoIterator<Item = Self>) -> Self {
        Self::normalized(expressions, false)
    }

    fn normalized(expressions: impl IntoIterator<Item = Self>, conjunction: bool) -> Self {
        let mut normalized = Vec::new();
        for expression in expressions {
            match expression {
                Self::All(nested) if conjunction => normalized.extend(nested),
                Self::Any(nested) if !conjunction => normalized.extend(nested),
                Self::Constant(value) if value == conjunction => {}
                Self::Constant(value) => return Self::Constant(value),
                expression => normalized.push(expression),
            }
        }
        normalized.sort_unstable();
        normalized.dedup();
        match normalized.len() {
            0 => Self::Constant(conjunction),
            1 => normalized.pop().expect("one Boolean guard expression"),
            _ if conjunction => Self::All(normalized),
            _ => Self::Any(normalized),
        }
    }

    fn implies(&self, required: &Self) -> bool {
        if self == required
            || matches!(self, Self::Constant(false))
            || matches!(required, Self::Constant(true))
        {
            return true;
        }
        if matches!(
            (self, required),
            (Self::Truthy(active), Self::Defined(required))
                | (Self::Undefined(active), Self::Falsy(required))
                if active == required
        ) {
            return true;
        }
        match self {
            Self::Any(active) => active.iter().all(|expression| expression.implies(required)),
            Self::All(active) => match required {
                Self::All(required) => required.iter().all(|expression| self.implies(expression)),
                _ => active.iter().any(|expression| expression.implies(required)),
            },
            _ => match required {
                Self::Any(required) => required.iter().any(|expression| self.implies(expression)),
                Self::All(required) => required.iter().all(|expression| self.implies(expression)),
                _ => false,
            },
        }
    }

    fn may_depend_on_macro(&self, macro_name: &str) -> bool {
        match self {
            Self::Defined(name)
            | Self::Undefined(name)
            | Self::Truthy(name)
            | Self::Falsy(name) => name == macro_name,
            // Opaque expressions have structured conditional ownership but no
            // structured macro operands, so any mutation may change them.
            Self::Opaque(_) | Self::NegatedOpaque(_) => true,
            Self::All(expressions) | Self::Any(expressions) => expressions
                .iter()
                .any(|expression| expression.may_depend_on_macro(macro_name)),
            Self::Constant(_) => false,
        }
    }

    pub fn heap_size(&self) -> usize {
        match self {
            Self::Defined(value)
            | Self::Undefined(value)
            | Self::Truthy(value)
            | Self::Falsy(value)
            | Self::Opaque(value)
            | Self::NegatedOpaque(value) => value.len(),
            Self::All(expressions) | Self::Any(expressions) => {
                expressions
                    .iter()
                    .fold(std::mem::size_of::<Vec<Self>>(), |size, expression| {
                        size.saturating_add(std::mem::size_of::<Self>())
                            .saturating_add(expression.heap_size())
                    })
            }
            Self::Constant(_) => 0,
        }
    }
}

impl PreprocessorGuard {
    fn as_boolean_expression(&self) -> Option<BooleanGuardExpression> {
        match self {
            Self::Defined(name) => Some(BooleanGuardExpression::Defined(name.clone())),
            Self::Undefined(name) => Some(BooleanGuardExpression::Undefined(name.clone())),
            Self::Boolean(expression) => Some(expression.clone()),
            Self::Constant(value) => Some(BooleanGuardExpression::Constant(*value)),
            Self::Expression(_) | Self::NegatedExpression(_) => None,
        }
    }

    fn negated(&self) -> Self {
        match self {
            Self::Defined(name) => Self::Undefined(name.clone()),
            Self::Undefined(name) => Self::Defined(name.clone()),
            Self::Boolean(expression) => Self::Boolean(expression.negated()),
            Self::Expression(expression) => Self::NegatedExpression(expression.clone()),
            Self::NegatedExpression(expression) => Self::Expression(expression.clone()),
            Self::Constant(value) => Self::Constant(!value),
        }
    }

    fn may_depend_on_macro(&self, macro_name: &str) -> bool {
        match self {
            Self::Defined(name) | Self::Undefined(name) => name == macro_name,
            Self::Boolean(expression) => expression.may_depend_on_macro(macro_name),
            // These expressions could not be lowered to a Boolean operand
            // tree, so their dependencies remain unknown.
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

/// The sentinel that gives a function-like macro replacement a parseable
/// statement context. The replacement text is copied in verbatim, so the only
/// bytes ahead of it are this prefix.
const MACRO_BODY_SENTINEL_PREFIX: &str = "void __bifrost_macro_body() { ";

/// A function-like macro replacement parsed inside a sentinel function body.
///
/// Tree-sitter keeps a `#define NAME(a) ...` replacement as one opaque
/// `preproc_arg`. Wrapping that exact byte slice in a function body recovers
/// its statements, declarations, and member calls as ordinary C++ structure.
/// The slice is copied verbatim at [`Self::body_offset`], so a node range in
/// [`Self::tree`] maps back onto the defining `preproc_arg` by subtracting
/// that offset.
pub struct ParsedReplacementBody {
    pub source: String,
    pub tree: Tree,
    pub body_offset: usize,
    pub parameters: Vec<String>,
}

impl ParsedReplacementBody {
    /// The sentinel function body holding the replacement's statements.
    pub fn statements(&self) -> Option<Node<'_>> {
        first_descendant_of_kind(self.tree.root_node(), "function_definition")?
            .child_by_field_name("body")
    }

    /// The byte range `node` occupies in the file that defines the macro.
    ///
    /// `replacement_start` is the defining `preproc_arg`'s start byte. The
    /// replacement is copied into the sentinel verbatim, so subtracting the
    /// body offset and adding that start is exact.
    pub fn file_range(&self, node: Node<'_>, replacement_start: usize) -> std::ops::Range<usize> {
        debug_assert!(node.start_byte() >= self.body_offset);
        let start = replacement_start + (node.start_byte() - self.body_offset);
        start..start + (node.end_byte() - node.start_byte())
    }

    /// Whether the replacement names the variadic argument pack.
    ///
    /// `__VA_ARGS__` parses as an ordinary identifier, so the sentinel tree
    /// gives no error for it even though the expansion it stands for is
    /// unknown at the definition. Reject it from the parsed tree rather than
    /// by scanning the replacement text.
    fn expands_variadic_arguments(&self) -> bool {
        let mut stack = vec![self.tree.root_node()];
        while let Some(node) = stack.pop() {
            if matches!(
                node.kind(),
                "identifier" | "type_identifier" | "field_identifier" | "namespace_identifier"
            ) && node_text(node, &self.source) == "__VA_ARGS__"
            {
                return true;
            }
            for index in (0..node.named_child_count()).rev() {
                if let Some(child) = node.named_child(index) {
                    stack.push(child);
                }
            }
        }
        false
    }
}

fn parse_cpp_integer_literal(text: &str) -> Option<i128> {
    let compact = text.chars().filter(|ch| *ch != '\'').collect::<String>();
    let (radix, digits_start, digit_matches): (u32, usize, fn(char) -> bool) =
        if compact.starts_with("0x") || compact.starts_with("0X") {
            (16, 2, |ch| ch.is_ascii_hexdigit())
        } else if compact.starts_with("0b") || compact.starts_with("0B") {
            (2, 2, |ch| matches!(ch, '0' | '1'))
        } else if compact.starts_with('0') && compact.len() > 1 {
            (8, 0, |ch| matches!(ch, '0'..='7'))
        } else {
            (10, 0, |ch| ch.is_ascii_digit())
        };
    let digit_len = compact[digits_start..]
        .chars()
        .take_while(|ch| digit_matches(*ch))
        .map(char::len_utf8)
        .sum::<usize>();
    if digit_len == 0 {
        return None;
    }
    let digits_end = digits_start + digit_len;
    if !compact[digits_end..]
        .chars()
        .all(|ch| matches!(ch, 'u' | 'U' | 'l' | 'L' | 'z' | 'Z'))
    {
        return None;
    }
    i128::from_str_radix(&compact[digits_start..digits_end], radix).ok()
}

#[derive(Clone)]
enum MacroLocalBindingTypeTemplate {
    Parameter(usize),
    Fixed(String),
}

#[derive(Clone)]
struct MacroLocalBindingTemplate {
    name: String,
    declared_type: MacroLocalBindingTypeTemplate,
    pointer_depth: i32,
}

/// A local declaration contributed by one structurally known function-like macro.
///
/// `type_node` points into the invocation syntax when the replacement's type
/// is one of the macro parameters. Consumers can therefore use their normal
/// lexical type resolver without parsing replacement text themselves.
pub struct MacroLocalBinding<'tree> {
    pub name: String,
    pub type_name: String,
    pub type_node: Option<Node<'tree>>,
    pub pointer_depth: i32,
}

/// Recover GLib's `g_autoptr(T) name = value` declaration from the CST shape
/// produced by tree-sitter-cpp for C source. The grammar retains the macro
/// invocation as the assignment's left operand and the declared name as one
/// adjacent `ERROR(identifier)` node, so no macro text splitting is needed.
fn recognized_c_macro_declarator_binding<'tree>(
    statement: Node<'tree>,
    source: &str,
) -> Option<MacroLocalBinding<'tree>> {
    let assignment = match statement.kind() {
        "assignment_expression" => statement,
        "expression_statement" if statement.named_child_count() == 1 => statement.named_child(0)?,
        _ => return None,
    };
    if assignment.kind() != "assignment_expression" {
        return None;
    }
    let call = assignment.child_by_field_name("left")?;
    if call.kind() != "call_expression" {
        return None;
    }
    let function = call.child_by_field_name("function")?;
    if function.kind() != "identifier" || node_text(function, source) != "g_autoptr" {
        return None;
    }
    let arguments = call.child_by_field_name("arguments")?;
    let mut actuals = argument_children(arguments);
    let type_node = actuals.next()?;
    if actuals.next().is_some()
        || !matches!(
            type_node.kind(),
            "identifier"
                | "type_identifier"
                | "qualified_identifier"
                | "scoped_type_identifier"
                | "template_type"
        )
    {
        return None;
    }
    let name_node = (0..assignment.named_child_count())
        .filter_map(|index| assignment.named_child(index))
        .filter(|child| child.kind() == "ERROR")
        .filter_map(|error| {
            (error.named_child_count() == 1)
                .then(|| error.named_child(0))
                .flatten()
        })
        .find(|node| node.kind() == "identifier")?;
    let name = node_text(name_node, source).trim();
    let type_name = node_text(type_node, source).trim();
    if name.is_empty() || type_name.is_empty() {
        return None;
    }
    Some(MacroLocalBinding {
        name: name.to_string(),
        type_name: type_name.to_string(),
        type_node: Some(type_node),
        pointer_depth: 1,
    })
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

    fn uncertain_from(current: &Self, source: &ProjectFile, declaration_byte: usize) -> Self {
        Self {
            source: source.clone(),
            declaration_byte,
            definition: current.definition.clone(),
            exact: false,
        }
    }
}

/// The preprocessor conditionals whose truth decides whether one macro event
/// applies, by the start byte of each conditional node. Empty means the event
/// is unconditional.
///
/// [`VisibilityIndex::macro_event_condition_value`] needs exactly the
/// conditional ancestors that structurally contain the event, and deciding
/// containment means asking [`cpp_displaced_preprocessor_boundary`] for an
/// `#endif` tree-sitter displaced into error recovery -- a walk of the
/// conditional's whole subtree. That answer is a fact about the tree alone, so
/// it is settled once, when the events are collected, instead of on every
/// replay of the event (#1496).
type OwningPreprocessorConditionals = Box<[usize]>;

#[derive(Clone)]
pub enum MacroEvent {
    Define {
        name: String,
        binding: MacroBinding,
        byte: usize,
        conditionals: OwningPreprocessorConditionals,
    },
    Undef {
        name: String,
        byte: usize,
        conditionals: OwningPreprocessorConditionals,
    },
    Include {
        targets: Vec<ProjectFile>,
        byte: usize,
        conditionals: OwningPreprocessorConditionals,
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

#[derive(Clone, PartialEq, Eq)]
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

    /// The request-scope proof this index was built with (issue #2414 step 3).
    pub fn token(&self) -> QueryToken<'a> {
        self.token
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
        token: QueryToken<'a>,
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
            token,
            visible_by_identifier: build_visible_identifier_index(
                &CppGraphSource::from_source(cpp, token),
                &visible_by_file,
                &visible_source_files_by_root,
                &mut global_field_internal_linkage,
            ),
            global_field_internal_linkage,
            visible_by_file,
            visible_source_files_by_root,
            alias_cells: Mutex::new(HashMap::default()),
            visible_parser_alias_name_sets: RwLock::new(HashMap::default()),
            ordinary_type_import_cells: Mutex::new(HashMap::default()),
            project_using_index: OnceLock::new(),
            callable_reference_specs: Mutex::new(HashMap::default()),
            include_activation_cells: Mutex::new(HashMap::default()),
            compile_proven_guard_cells: Mutex::new(HashMap::default()),
            conditional_include_projection_cells: Mutex::new(HashMap::default()),
            conditional_include_projection_index_build_count: AtomicUsize::new(0),
            conditional_include_projection_state_count: AtomicUsize::new(0),
            conditional_include_target_state_count: AtomicUsize::new(0),
            include_activation_build_count: AtomicUsize::new(0),
            using_donor_activation_count: AtomicUsize::new(0),
            using_namespace_lookup_count: AtomicUsize::new(0),
            using_name_candidate_inspection_count: AtomicUsize::new(0),
            callable_reference_spec_build_count: AtomicUsize::new(0),
            alias_source_parse_counts: Mutex::new(HashMap::default()),
            visible_parser_alias_name_set_build_count: AtomicUsize::new(0),
            parser_alias_fallback_calls: AtomicUsize::new(0),
            parser_alias_fallback_files: AtomicUsize::new(0),
            parser_alias_source_parses: AtomicUsize::new(0),
            parser_alias_fallback_elapsed_micros: AtomicUsize::new(0),
            field_type_facts: Mutex::new(HashMap::default()),
            structured_alias_targets: Mutex::new(HashMap::default()),
            callable_comparables: Mutex::new(HashMap::default()),
            indexed_structural_class_scopes: Mutex::new(HashMap::default()),
            indexed_enclosing_owner_scopes: Mutex::new(HashMap::default()),
            precise_parent_cache: Mutex::new(HashMap::default()),
            macro_event_cells: Mutex::new(HashMap::default()),
            macro_include_protection_cells: Mutex::new(HashMap::default()),
            macro_environment_checkpoints: Mutex::new(HashMap::default()),
            macro_replacements: Mutex::new(HashMap::default()),
            macro_local_binding_templates: Mutex::new(HashMap::default()),
            macro_replacement_bodies: Mutex::new(HashMap::default()),
            callable_parameter_macro_arities: Mutex::new(HashMap::default()),
            macro_replacement_parse_count: AtomicUsize::new(0),
            macro_event_application_count: AtomicUsize::new(0),
            macro_environment_checkpoint_build_count: AtomicUsize::new(0),
            macro_environment_copy_count: AtomicUsize::new(0),
            macro_environment_request_count: AtomicUsize::new(0),
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
        CppGraphSource::from_source(self.cpp, self.token)
    }

    pub fn build(
        cpp: &'a dyn CppSource,
        token: QueryToken<'a>,
        analyzer: &CppGraphSource<'_>,
        roots: &HashSet<ProjectFile>,
    ) -> Self {
        Self::build_with_cancellation(cpp, token, analyzer, roots, None)
    }

    pub fn build_with_cancellation(
        cpp: &'a dyn CppSource,
        token: QueryToken<'a>,
        analyzer: &CppGraphSource<'_>,
        roots: &HashSet<ProjectFile>,
        cancellation: Option<&CancellationToken>,
    ) -> Self {
        let visibility_started = Instant::now();
        let include_targets = cpp.include_target_index();
        let includes_started = Instant::now();
        let mut include_graph = IncludeGraph::default();
        for root in roots {
            include_graph.extend_with(root, cancellation, &mut |file| {
                cpp_include_paths(&cpp.visibility_import_statements(token, file))
                    .into_iter()
                    .flat_map(|include| {
                        resolve_include_targets_with_index(file, &include, include_targets)
                    })
                    .collect()
            });
        }
        let include_elapsed = includes_started.elapsed();
        let include_file_count = include_graph.files().count();
        let visible_source_files_by_root = roots
            .iter()
            .map(|root| {
                (
                    root.clone(),
                    include_graph.reachable_files(root, cancellation),
                )
            })
            .collect::<HashMap<_, _>>();
        let mut visibility_stats = BoundedVisibilityStats::default();
        let mut visible_by_file = build_bounded_visible_declarations(
            cpp,
            token,
            analyzer,
            roots,
            &visible_source_files_by_root,
            cancellation,
            &mut visibility_stats,
        );
        if std::env::var_os("BIFROST_CPP_VISIBILITY_STATS").is_some() {
            eprintln!(
                "BIFROST_CPP_VISIBILITY_STATS total_ms={} include_ms={} include_files={} rounds={} root_names={} identifier_lookups={} candidate_units={} candidate_sources={} declaration_reads={} declaration_units={} selected_units={} dependency_ast_nodes={} dependency_names={} lookup_ms={} declaration_ms={} dependency_ast_ms={}",
                visibility_started.elapsed().as_millis(),
                include_elapsed.as_millis(),
                include_file_count,
                visibility_stats.rounds,
                visibility_stats.root_names,
                visibility_stats.identifier_lookups,
                visibility_stats.candidate_units,
                visibility_stats.candidate_sources,
                visibility_stats.declaration_reads,
                visibility_stats.declaration_units,
                visibility_stats.selected_units,
                visibility_stats.dependency_ast_nodes,
                visibility_stats.dependency_names,
                visibility_stats.lookup_elapsed.as_millis(),
                visibility_stats.declaration_elapsed.as_millis(),
                visibility_stats.dependency_ast_elapsed.as_millis(),
            );
        }
        let report_stats = std::env::var_os("BIFROST_CPP_VISIBILITY_STATS").is_some();
        let finalize_started = Instant::now();
        if report_stats {
            eprintln!(
                "BIFROST_CPP_VISIBILITY_FINALIZE_STATS status=started roots={} visible_units={}",
                visible_by_file.len(),
                visible_by_file.values().map(HashSet::len).sum::<usize>(),
            );
        }
        let owner_started = Instant::now();
        if report_stats {
            eprintln!("BIFROST_CPP_VISIBILITY_FINALIZE_STATS phase=owners status=started");
        }
        let owner_stats = extend_with_out_of_line_owner_bindings(cpp, &mut visible_by_file);
        if report_stats {
            eprintln!(
                "BIFROST_CPP_VISIBILITY_FINALIZE_STATS phase=owners status=completed unseen_owners={} definition_lookups={} admitted={} elapsed_ms={}",
                owner_stats.unseen_owners,
                owner_stats.definition_lookups,
                owner_stats.admitted,
                owner_started.elapsed().as_millis(),
            );
        }
        let mut global_field_internal_linkage = HashMap::default();
        let identifier_started = Instant::now();
        if report_stats {
            eprintln!(
                "BIFROST_CPP_VISIBILITY_FINALIZE_STATS phase=identifier_index status=started"
            );
        }
        let visible_by_identifier = build_visible_identifier_index(
            analyzer,
            &visible_by_file,
            &visible_source_files_by_root,
            &mut global_field_internal_linkage,
        );
        if report_stats {
            eprintln!(
                "BIFROST_CPP_VISIBILITY_FINALIZE_STATS phase=identifier_index status=completed roots={} names={} candidates={} elapsed_ms={}",
                visible_by_identifier.len(),
                visible_by_identifier
                    .values()
                    .map(HashMap::len)
                    .sum::<usize>(),
                visible_by_identifier
                    .values()
                    .flat_map(HashMap::values)
                    .map(Vec::len)
                    .sum::<usize>(),
                identifier_started.elapsed().as_millis(),
            );
        }
        let mut cpp_template_metadata = HashMap::default();
        let metadata_started = Instant::now();
        let mut template_classes = 0usize;
        if report_stats {
            eprintln!(
                "BIFROST_CPP_VISIBILITY_FINALIZE_STATS phase=template_metadata status=started"
            );
        }
        for unit in visible_by_file
            .values()
            .flatten()
            .filter(|unit| unit.is_class())
        {
            template_classes += 1;
            if cpp_template_metadata.contains_key(unit) {
                continue;
            }
            if let Some(metadata) = cpp.template_metadata(unit) {
                cpp_template_metadata.insert(unit.clone(), metadata);
            }
        }
        if report_stats {
            eprintln!(
                "BIFROST_CPP_VISIBILITY_FINALIZE_STATS phase=template_metadata status=completed classes={} metadata={} elapsed_ms={}",
                template_classes,
                cpp_template_metadata.len(),
                metadata_started.elapsed().as_millis(),
            );
        }
        let families_started = Instant::now();
        if report_stats {
            eprintln!(
                "BIFROST_CPP_VISIBILITY_FINALIZE_STATS phase=template_families status=started"
            );
        }
        let mut cpp_template_families: HashMap<String, Vec<CodeUnit>> = HashMap::default();
        for (unit, metadata) in &cpp_template_metadata {
            cpp_template_families
                .entry(metadata.primary_fq_name.clone())
                .or_default()
                .push(unit.clone());
        }
        // `cpp_template_metadata` is hash-keyed on `CodeUnit`, so the push
        // order above is a function of those hashes. Two mirrored headers can
        // declare one specialization; `select_template_specialization` treats
        // them as interchangeable and returns the family's first entry, so an
        // unsorted family made the reported declaration depend on the
        // workspace's absolute path and on unrelated files (#1836). Order the
        // family exactly as `build_visible_identifier_index` orders its
        // per-identifier candidate lists.
        for family in cpp_template_families.values_mut() {
            sort_lookup_units(family);
        }
        if report_stats {
            eprintln!(
                "BIFROST_CPP_VISIBILITY_FINALIZE_STATS phase=template_families status=completed families={} members={} elapsed_ms={}",
                cpp_template_families.len(),
                cpp_template_families.values().map(Vec::len).sum::<usize>(),
                families_started.elapsed().as_millis(),
            );
            eprintln!(
                "BIFROST_CPP_VISIBILITY_FINALIZE_STATS status=completed roots={} visible_units={} elapsed_ms={} total_ms={}",
                visible_by_file.len(),
                visible_by_file.values().map(HashSet::len).sum::<usize>(),
                finalize_started.elapsed().as_millis(),
                visibility_started.elapsed().as_millis(),
            );
        }
        Self {
            cpp,
            token,
            visible_by_file,
            visible_by_identifier,
            global_field_internal_linkage,
            visible_source_files_by_root,
            alias_cells: Mutex::new(HashMap::default()),
            visible_parser_alias_name_sets: RwLock::new(HashMap::default()),
            ordinary_type_import_cells: Mutex::new(HashMap::default()),
            project_using_index: OnceLock::new(),
            callable_reference_specs: Mutex::new(HashMap::default()),
            include_activation_cells: Mutex::new(HashMap::default()),
            compile_proven_guard_cells: Mutex::new(HashMap::default()),
            conditional_include_projection_cells: Mutex::new(HashMap::default()),
            #[cfg(any(test, feature = "test-support"))]
            conditional_include_projection_index_build_count: AtomicUsize::new(0),
            #[cfg(any(test, feature = "test-support"))]
            conditional_include_projection_state_count: AtomicUsize::new(0),
            #[cfg(any(test, feature = "test-support"))]
            conditional_include_target_state_count: AtomicUsize::new(0),
            #[cfg(any(test, feature = "test-support"))]
            include_activation_build_count: AtomicUsize::new(0),
            #[cfg(any(test, feature = "test-support"))]
            using_donor_activation_count: AtomicUsize::new(0),
            #[cfg(any(test, feature = "test-support"))]
            using_namespace_lookup_count: AtomicUsize::new(0),
            #[cfg(any(test, feature = "test-support"))]
            using_name_candidate_inspection_count: AtomicUsize::new(0),
            #[cfg(any(test, feature = "test-support"))]
            callable_reference_spec_build_count: AtomicUsize::new(0),
            #[cfg(any(test, feature = "test-support"))]
            alias_source_parse_counts: Mutex::new(HashMap::default()),
            #[cfg(any(test, feature = "test-support"))]
            visible_parser_alias_name_set_build_count: AtomicUsize::new(0),
            parser_alias_fallback_calls: AtomicUsize::new(0),
            parser_alias_fallback_files: AtomicUsize::new(0),
            parser_alias_source_parses: AtomicUsize::new(0),
            parser_alias_fallback_elapsed_micros: AtomicUsize::new(0),
            field_type_facts: Mutex::new(HashMap::default()),
            structured_alias_targets: Mutex::new(HashMap::default()),
            callable_comparables: Mutex::new(HashMap::default()),
            indexed_structural_class_scopes: Mutex::new(HashMap::default()),
            indexed_enclosing_owner_scopes: Mutex::new(HashMap::default()),
            precise_parent_cache: Mutex::new(HashMap::default()),
            macro_event_cells: Mutex::new(HashMap::default()),
            macro_include_protection_cells: Mutex::new(HashMap::default()),
            macro_environment_checkpoints: Mutex::new(HashMap::default()),
            macro_replacements: Mutex::new(HashMap::default()),
            macro_local_binding_templates: Mutex::new(HashMap::default()),
            macro_replacement_bodies: Mutex::new(HashMap::default()),
            callable_parameter_macro_arities: Mutex::new(HashMap::default()),
            #[cfg(any(test, feature = "test-support"))]
            macro_replacement_parse_count: AtomicUsize::new(0),
            #[cfg(any(test, feature = "test-support"))]
            macro_event_application_count: AtomicUsize::new(0),
            #[cfg(any(test, feature = "test-support"))]
            macro_environment_checkpoint_build_count: AtomicUsize::new(0),
            #[cfg(any(test, feature = "test-support"))]
            macro_environment_copy_count: AtomicUsize::new(0),
            #[cfg(any(test, feature = "test-support"))]
            macro_environment_request_count: AtomicUsize::new(0),
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
        self.call_arity_evidence_at(file, call, source, call.start_byte())
    }

    /// Argument-count evidence for a call whose macro environment is not the
    /// one at its own byte offset.
    ///
    /// A call recovered from a macro replacement lives in a sentinel parse of
    /// its own, so its node offsets say nothing about which macros are active.
    /// `environment_byte` names the position in `file` whose macro environment
    /// governs the call: the macro definition site for a replacement body.
    pub fn call_arity_evidence_at(
        &self,
        file: &ProjectFile,
        call: Node<'_>,
        source: &str,
        environment_byte: usize,
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
        let recovered_c_keyword_arguments =
            recovered_c_keyword_argument_count(file, call, arguments, source);
        let arguments = argument_children(arguments).collect::<Vec<_>>();
        if arguments
            .iter()
            .all(|argument| !argument_shape_may_change_arity(*argument))
        {
            return CallArityEvidence::Exact(arguments.len() + recovered_c_keyword_arguments);
        }
        let environment = self.macro_environment(file, environment_byte);
        let mut stack = Vec::new();
        let mut total = recovered_c_keyword_arguments;
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
        if !binding.is_exact() {
            return CallArityEvidence::Unknown;
        }
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

    /// Recover a typed local declared by an active C function-like macro.
    ///
    /// This is intentionally narrower than macro expansion. The replacement
    /// must parse as one declaration, and the invocation must bind every
    /// formal parameter to one structured argument. That is sufficient for
    /// declaration macros such as `THIS(StorageAzure)`. An unavailable include
    /// can make the binding provisional without erasing its last known
    /// definition; an explicit conflicting definition still replaces it with
    /// Unsupported. Malformed and statement-producing macros also fail closed.
    pub fn function_macro_local_binding<'tree>(
        &self,
        file: &ProjectFile,
        statement: Node<'tree>,
        source: &str,
    ) -> Option<MacroLocalBinding<'tree>> {
        if !is_c_source_file(file) {
            return None;
        }
        if let Some(binding) = recognized_c_macro_declarator_binding(statement, source) {
            return Some(binding);
        }
        let call = match statement.kind() {
            "call_expression" => statement,
            "expression_statement" if statement.named_child_count() == 1 => {
                statement.named_child(0)?
            }
            _ => return None,
        };
        if call.kind() != "call_expression" {
            return None;
        }
        let function = call.child_by_field_name("function")?;
        if function.kind() != "identifier" {
            return None;
        }
        let arguments = call.child_by_field_name("arguments")?;
        let actuals = argument_children(arguments).collect::<Vec<_>>();
        let environment = self.macro_environment(file, call.start_byte());
        let function_name = node_text(function, source);
        let binding = environment.binding(function_name)?;
        let MacroDefinition::Function {
            parameters,
            replacement,
        } = &binding.definition
        else {
            return None;
        };
        if actuals.len() != parameters.len() {
            return None;
        }
        let template = self.macro_local_binding_template(binding, parameters, replacement)?;
        let (type_name, type_node) = match &template.declared_type {
            MacroLocalBindingTypeTemplate::Parameter(index) => {
                let actual = *actuals.get(*index)?;
                if !macro_expansion_shape_is_safe(actual, source, &[], &environment) {
                    return None;
                }
                (node_text(actual, source).trim().to_string(), Some(actual))
            }
            MacroLocalBindingTypeTemplate::Fixed(type_name) => (type_name.clone(), None),
        };
        if type_name.is_empty() {
            return None;
        }
        Some(MacroLocalBinding {
            name: template.name.clone(),
            type_name,
            type_node,
            pointer_depth: template.pointer_depth,
        })
    }

    fn macro_local_binding_template(
        &self,
        binding: &MacroBinding,
        parameters: &[String],
        replacement: &str,
    ) -> Option<Arc<MacroLocalBindingTemplate>> {
        let key = (binding.source.clone(), binding.declaration_byte);
        if let Some(template) = self
            .macro_local_binding_templates
            .lock()
            .expect("C++ macro local-binding cache poisoned")
            .get(&key)
        {
            return template.clone();
        }
        let template = (|| {
            let body = self.parsed_macro_replacement_body(&key, parameters, replacement)?;
            let sentinel = body.source.as_str();
            let statements = body.statements()?;
            if statements.named_child_count() != 1 {
                return None;
            }
            let declaration = statements.named_child(0)?;
            if declaration.kind() != "declaration" {
                return None;
            }
            let type_node = declaration
                .child_by_field_name("type")
                .or_else(|| first_type_child(declaration))?;
            let declarator = declaration.child_by_field_name("declarator").or_else(|| {
                let mut cursor = declaration.walk();
                declaration.named_children(&mut cursor).find_map(|child| {
                    if child.kind() == "init_declarator" {
                        child.child_by_field_name("declarator")
                    } else {
                        is_declarator_node(child).then_some(child)
                    }
                })
            })?;
            let name = extract_variable_name(declarator, sentinel)?;
            let pointer_depth = declared_name_indirection(declaration, type_node, &name, sentinel)?;
            let type_text = node_text(type_node, sentinel).trim();
            let declared_type = parameters
                .iter()
                .position(|parameter| parameter == type_text)
                .map(MacroLocalBindingTypeTemplate::Parameter)
                .unwrap_or_else(|| MacroLocalBindingTypeTemplate::Fixed(type_text.to_string()));
            Some(Arc::new(MacroLocalBindingTemplate {
                name,
                declared_type,
                pointer_depth,
            }))
        })();
        self.macro_local_binding_templates
            .lock()
            .expect("C++ macro local-binding cache poisoned")
            .insert(key, template.clone());
        template
    }

    /// The parsed replacement body of the function-like macro `definition`
    /// defines, or `None` when the replacement cannot be recovered exactly.
    ///
    /// `definition` is the defining `preproc_function_def` node in `file`, so
    /// the result describes that definition rather than whichever same-named
    /// macro a later reference resolves to.
    pub fn function_macro_replacement_body(
        &self,
        file: &ProjectFile,
        definition: Node<'_>,
        source: &str,
    ) -> Option<Arc<ParsedReplacementBody>> {
        debug_assert_eq!(definition.kind(), "preproc_function_def");
        let MacroDefinition::Function {
            parameters,
            replacement,
        } = Self::decode_macro_definition(definition, source)
        else {
            return None;
        };
        self.parsed_macro_replacement_body(
            &(file.clone(), definition.start_byte()),
            &parameters,
            &replacement,
        )
    }

    /// Parse one function-like macro replacement inside the shared sentinel.
    ///
    /// The parse fails closed, and the failure is cached, whenever the
    /// sentinel tree carries an error or the replacement uses preprocessor
    /// syntax that has no C++ meaning. Token pasting and stringizing produce
    /// `ERROR` nodes; `__VA_ARGS__` parses as an ordinary identifier and is
    /// therefore rejected from the parsed tree instead of the source text.
    fn parsed_macro_replacement_body(
        &self,
        key: &(ProjectFile, usize),
        parameters: &[String],
        replacement: &str,
    ) -> Option<Arc<ParsedReplacementBody>> {
        if let Some(body) = self
            .macro_replacement_bodies
            .lock()
            .expect("C++ macro replacement body cache poisoned")
            .get(key)
        {
            return body.clone();
        }
        let body = (|| {
            if replacement.trim().is_empty() {
                return None;
            }
            let source = format!("{MACRO_BODY_SENTINEL_PREFIX}{replacement}; }}");
            let mut parser = Parser::new();
            parser
                .set_language(&tree_sitter_cpp::LANGUAGE.into())
                .ok()?;
            let tree = parser.parse(&source, None)?;
            if tree.root_node().has_error() {
                return None;
            }
            let body = ParsedReplacementBody {
                source,
                tree,
                body_offset: MACRO_BODY_SENTINEL_PREFIX.len(),
                parameters: parameters.to_vec(),
            };
            body.statements()?;
            if body.expands_variadic_arguments() {
                return None;
            }
            Some(Arc::new(body))
        })();
        self.macro_replacement_bodies
            .lock()
            .expect("C++ macro replacement body cache poisoned")
            .insert(key.clone(), body.clone());
        body
    }

    fn decode_macro_definition(node: Node<'_>, source: &str) -> MacroDefinition {
        let replacement = node
            .child_by_field_name("value")
            .map(|value| node_text(value, source).to_string())
            .unwrap_or_default();
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

    fn macro_environment_checkpoint_cell(
        &self,
        file: &ProjectFile,
    ) -> MacroEnvironmentCheckpointCell {
        self.macro_environment_checkpoints
            .lock()
            .expect("C++ macro environment checkpoint cache poisoned")
            .entry(file.clone())
            .or_default()
            .clone()
    }

    /// The environment of `file`'s macro events applied up to `before_byte`.
    pub fn macro_environment(
        &self,
        file: &ProjectFile,
        before_byte: usize,
    ) -> Arc<MacroEnvironment> {
        #[cfg(any(test, feature = "test-support"))]
        self.macro_environment_request_count
            .fetch_add(1, Ordering::Relaxed);
        let cell = self.macro_event_cell(file);
        let events = cell.get_or_init(|| self.collect_macro_events(file).into_boxed_slice());
        let frontier = events.partition_point(|event| event.byte() < before_byte);
        let checkpoint_cell = self.macro_environment_checkpoint_cell(file);
        let checkpoints =
            checkpoint_cell.get_or_init(|| self.build_macro_environment_checkpoints(file, events));
        let checkpoint = checkpoints.at_or_before(frontier);
        if checkpoint.frontier == frontier {
            return Arc::clone(&checkpoint.environment);
        }
        #[cfg(any(test, feature = "test-support"))]
        self.macro_environment_copy_count
            .fetch_add(1, Ordering::Relaxed);
        let mut environment = checkpoint.environment.as_ref().clone();
        let mut include_stack = HashSet::from_iter([file.clone()]);
        for event in &events[checkpoint.frontier..frontier] {
            self.apply_macro_event(file, event, &mut environment, &mut include_stack);
        }
        Arc::new(environment)
    }

    /// Apply `file`'s events once, keeping the environment at the prefixes
    /// [`MacroEnvironmentCheckpoints`] describes.
    fn build_macro_environment_checkpoints(
        &self,
        file: &ProjectFile,
        events: &[MacroEvent],
    ) -> MacroEnvironmentCheckpoints {
        #[cfg(any(test, feature = "test-support"))]
        self.macro_environment_checkpoint_build_count
            .fetch_add(1, Ordering::Relaxed);
        // The TU's build-proven defines hold from the first byte (#2011): they
        // are facts of the whole compile, so they seed the frontier-zero
        // checkpoint. A later explicit #undef event still overrides them
        // through `known_undefined_names`.
        let mut environment = MacroEnvironment {
            build_proven_defines: self
                .compile_proven_guards(file)
                .iter()
                .filter_map(|guard| match guard {
                    PreprocessorGuard::Defined(name) => Some(name.clone()),
                    _ => None,
                })
                .collect(),
            ..MacroEnvironment::default()
        };
        let mut checkpoints = vec![MacroEnvironmentCheckpoint {
            frontier: 0,
            environment: Arc::new(environment.clone()),
        }];
        let mut include_stack = HashSet::from_iter([file.clone()]);
        for (index, event) in events.iter().enumerate() {
            self.apply_macro_event(file, event, &mut environment, &mut include_stack);
            let frontier = index + 1;
            if frontier % MACRO_ENVIRONMENT_CHECKPOINT_STRIDE == 0
                || matches!(event, MacroEvent::Include { .. })
            {
                checkpoints.push(MacroEnvironmentCheckpoint {
                    frontier,
                    environment: Arc::new(environment.clone()),
                });
            }
        }
        MacroEnvironmentCheckpoints { checkpoints }
    }

    /// Whether `name` is bound as a macro at `before_byte` in `file`,
    /// including a binding this environment cannot pin to one replacement
    /// (a conditional `#define`, or a function-like macro).
    ///
    /// [`Self::object_macro_replacement_at`] collapses every such binding to
    /// `None`, which is indistinguishable from "not a macro at all". A caller
    /// that must not read a macro token as an ordinary type name needs the two
    /// apart: an unexpandable macro is an unknown, a plain identifier is not.
    pub fn names_a_macro_at(&self, file: &ProjectFile, name: &str, before_byte: usize) -> bool {
        self.macro_environment(file, before_byte)
            .binding(name)
            .is_some()
    }

    pub fn macro_name_may_be_bound_at(
        &self,
        file: &ProjectFile,
        name: &str,
        before_byte: usize,
    ) -> bool {
        self.macro_environment(file, before_byte).may_bind(name)
    }

    /// Whether the active macro binding at this reference is the requested
    /// indexed definition. Name equality alone is not enough because two
    /// headers can define the same macro for different translation units.
    pub fn macro_binding_matches_target_at(
        &self,
        analyzer: &CppGraphSource<'_>,
        file: &ProjectFile,
        name: &str,
        before_byte: usize,
        target: &CodeUnit,
    ) -> bool {
        let environment = self.macro_environment(file, before_byte);
        let Some(binding) = environment.binding(name) else {
            return false;
        };
        if binding.definition == MacroDefinition::Unsupported {
            return false;
        }
        // A normal header guard makes the replacement text conditional, but
        // it does not erase the definition site's source and byte identity.
        // Keep that identity even when expansion details are not exact.
        if binding.source != *target.source() {
            return false;
        }
        let Some(prepared) = self.cpp.prepared_syntax(self.token, target.source()) else {
            return false;
        };
        analyzer.ranges(target).iter().any(|range| {
            let Some(mut node) = node_for_exact_range(prepared.tree().root_node(), range) else {
                return false;
            };
            while !matches!(node.kind(), "preproc_def" | "preproc_function_def") {
                let Some(parent) = node.parent() else {
                    return false;
                };
                node = parent;
            }
            node.start_byte() == binding.declaration_byte
        })
    }

    /// Resolve an ordinary expression-position macro token at its exact byte.
    ///
    /// Calls and preprocessor-condition tokens have separate resolution
    /// surfaces. Declaration names, macro parameters, and labels are not
    /// references. Keeping that role policy here makes forward and both
    /// inverse graph builders consume the same activation verdict (#2093).
    pub fn resolve_ordinary_macro_reference(
        &self,
        analyzer: &CppGraphSource<'_>,
        file: &ProjectFile,
        node: Node<'_>,
        source: &str,
    ) -> OrdinaryMacroReferenceResolution {
        if !is_ordinary_macro_reference_node(node) {
            return OrdinaryMacroReferenceResolution::Missing;
        }
        let name = node_text(node, source);
        if name.is_empty() {
            return OrdinaryMacroReferenceResolution::Missing;
        }
        let visible = self
            .visible_identifier_candidates(file, name)
            .filter(|candidate| candidate.is_macro())
            .cloned()
            .collect::<Vec<_>>();
        let mut exact = Vec::new();
        for candidate in &visible {
            if self.macro_binding_matches_target_at(
                analyzer,
                file,
                name,
                node.start_byte(),
                candidate,
            ) && !exact
                .iter()
                .any(|existing| same_visible_symbol(existing, candidate))
            {
                exact.push(candidate.clone());
            }
        }
        match exact.len() {
            1 => OrdinaryMacroReferenceResolution::Resolved(exact.pop().unwrap()),
            2.. => OrdinaryMacroReferenceResolution::Ambiguous,
            0 if !visible.is_empty()
                && self.macro_name_may_be_bound_at(file, name, node.start_byte()) =>
            {
                OrdinaryMacroReferenceResolution::Ambiguous
            }
            0 => OrdinaryMacroReferenceResolution::Missing,
        }
    }

    /// Collect reference-capable C tokens beneath tree-sitter recovery nodes.
    ///
    /// The ordinary census deliberately skips every `ERROR` subtree. This
    /// separate, precision-only frontier admits only roles that retain enough
    /// structure for the C usage graph to interpret independently (#2089).
    /// Macro evidence comes from this visibility index at the exact byte; no
    /// source-text parsing or terminal-name fallback is used.
    pub fn recovered_c_reference_ranges(
        &self,
        file: &ProjectFile,
        root: Node<'_>,
        source: &str,
        limit: usize,
    ) -> RecoveredCReferenceRanges {
        if !is_c_source_file(file) {
            return RecoveredCReferenceRanges::Complete(Vec::new());
        }
        let mut ranges = Vec::new();
        let mut seen = HashSet::default();
        let mut stack = vec![(root, root.is_error())];
        while let Some((node, inside_error)) = stack.pop() {
            let inside_error = inside_error || node.is_error();
            if inside_error
                && recovered_c_reference_node(self, file, node, source)
                && seen.insert((node.start_byte(), node.end_byte()))
            {
                if ranges.len() == limit {
                    return RecoveredCReferenceRanges::LimitExceeded;
                }
                ranges.push(Range {
                    start_byte: node.start_byte(),
                    end_byte: node.end_byte(),
                    start_line: node.start_position().row,
                    end_line: node.end_position().row,
                });
            }
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                stack.push((child, inside_error));
            }
        }
        ranges.sort_unstable();
        RecoveredCReferenceRanges::Complete(ranges)
    }

    /// Whether this target is an indexed macro visible from this file.
    ///
    /// An unresolved conditional can make more than one same-name macro a
    /// possible active binding. Each possible target can keep the site as an
    /// unproven hit. A macro in an unrelated translation unit stays excluded.
    pub fn macro_target_is_visible_candidate(&self, file: &ProjectFile, target: &CodeUnit) -> bool {
        self.visible_identifier_candidates(file, target.identifier())
            .filter(|candidate| candidate.is_macro())
            .any(|candidate| {
                candidate.source() == target.source() && candidate.fq_name() == target.fq_name()
            })
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
        if self.cpp.prepared_syntax(self.token, file).is_none() {
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
                conditionals,
                byte,
            } => match self.macro_event_condition_value(file, *byte, environment, conditionals) {
                Some(true) => environment.insert(name.clone(), binding.clone()),
                Some(false) => {}
                None => Self::merge_conditional_macro_definition(
                    environment,
                    name,
                    binding,
                    file,
                    *byte,
                ),
            },
            MacroEvent::Undef {
                name,
                conditionals,
                byte,
            } => match self.macro_event_condition_value(file, *byte, environment, conditionals) {
                Some(true) => environment.remove(name),
                Some(false) => {}
                None => {
                    if environment.binding(name).is_some() {
                        environment.insert(name.clone(), MacroBinding::ambiguous(file, *byte));
                    }
                }
            },
            MacroEvent::Include {
                targets,
                conditionals,
                byte,
            } => {
                let condition =
                    self.macro_event_condition_value(file, *byte, environment, conditionals);
                if condition == Some(false) {
                    return;
                }
                if targets.is_empty() {
                    environment.mark_unknown_names(file, *byte);
                    return;
                }
                if condition.is_none() || targets.len() > 1 {
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
                    *binding = MacroBinding::uncertain_from(binding, file, *byte);
                }
            }
        }
    }

    /// Evaluate the structured conditional path that owns one macro event.
    ///
    /// `Some(true)` and `Some(false)` are proofs from exact macro bindings at
    /// this source byte. `None` preserves the old conditional merge when a
    /// build/configuration input or an unsupported expression is involved.
    ///
    /// `conditionals` is the event's own [`OwningPreprocessorConditionals`]:
    /// which ancestors structurally own the event was decided when the events
    /// were collected, so all this walk does is find those nodes again and ask
    /// the environment what their conditions are worth here.
    fn macro_event_condition_value(
        &self,
        file: &ProjectFile,
        event_byte: usize,
        environment: &MacroEnvironment,
        conditionals: &OwningPreprocessorConditionals,
    ) -> Option<bool> {
        if conditionals.is_empty() {
            return Some(true);
        }
        let prepared = self.cpp.prepared_syntax(self.token, file)?;
        let source = prepared.source();
        let root = prepared.tree().root_node();
        let descendant = root.descendant_for_byte_range(
            event_byte,
            event_byte.saturating_add(1).min(source.len()),
        )?;
        let mut unknown = false;
        let mut current = descendant.parent();
        while let Some(conditional) = current {
            if matches!(
                conditional.kind(),
                "preproc_if" | "preproc_ifdef" | "preproc_elif"
            ) && conditionals.contains(&conditional.start_byte())
            {
                let mut value = match conditional.kind() {
                    "preproc_ifdef" => {
                        let name = conditional.child_by_field_name("name")?;
                        let defined =
                            self.macro_name_defined_value(environment, node_text(name, source));
                        match conditional.child(0)?.kind() {
                            "#ifdef" => defined,
                            "#ifndef" => defined.map(|defined| !defined),
                            _ => None,
                        }
                    }
                    "preproc_if" | "preproc_elif" => conditional
                        .child_by_field_name("condition")
                        .and_then(|condition| {
                            self.preprocessor_integer_value(
                                condition,
                                source,
                                environment,
                                &mut Vec::new(),
                                0,
                            )
                        })
                        .map(|value| value != 0),
                    _ => unreachable!(),
                };
                if conditional
                    .child_by_field_name("alternative")
                    .is_some_and(|alternative| {
                        alternative.start_byte() <= descendant.start_byte()
                            && descendant.end_byte() <= alternative.end_byte()
                    })
                {
                    value = value.map(|value| !value);
                }
                match value {
                    Some(true) => {}
                    Some(false) => return Some(false),
                    None => unknown = true,
                }
            }
            current = conditional.parent();
        }
        (!unknown).then_some(true)
    }

    fn macro_name_defined_value(&self, environment: &MacroEnvironment, name: &str) -> Option<bool> {
        if environment.known_undefined_names.contains(name) {
            return Some(false);
        }
        if let Some(binding) = environment.binding(name) {
            return binding.is_exact().then_some(true);
        }
        environment
            .build_proven_defines
            .contains(name)
            .then_some(true)
    }

    fn preprocessor_integer_value(
        &self,
        expression: Node<'_>,
        source: &str,
        environment: &MacroEnvironment,
        expansion_stack: &mut Vec<(ProjectFile, usize)>,
        depth: usize,
    ) -> Option<i128> {
        // Macro replacement graphs can cycle. This explicit bound makes the
        // otherwise recursive AST evaluation stack-safe for hostile input.
        if depth >= 64 {
            return None;
        }
        match expression.kind() {
            "number_literal" => parse_cpp_integer_literal(node_text(expression, source)),
            "identifier" | "type_identifier" => {
                let binding = environment.binding(node_text(expression, source))?;
                if !binding.is_exact() {
                    return None;
                }
                let MacroDefinition::Object { replacement } = &binding.definition else {
                    return None;
                };
                let identity = (binding.source.clone(), binding.declaration_byte);
                if expansion_stack.contains(&identity) {
                    return None;
                }
                expansion_stack.push(identity);
                let parsed = self.parsed_macro_replacement(binding, replacement);
                let value = match parsed.as_ref() {
                    ParsedMacroReplacement::Parsed {
                        source: replacement_source,
                        tree,
                    } => first_descendant_of_kind(tree.root_node(), "call_expression")
                        .and_then(|call| call.child_by_field_name("arguments"))
                        .and_then(|arguments| argument_children(arguments).next())
                        .and_then(|argument| {
                            self.preprocessor_integer_value(
                                argument,
                                replacement_source,
                                environment,
                                expansion_stack,
                                depth + 1,
                            )
                        }),
                    ParsedMacroReplacement::Unsupported => None,
                };
                expansion_stack.pop();
                value
            }
            "preproc_defined" => {
                let mut cursor = expression.walk();
                let name = expression
                    .named_children(&mut cursor)
                    .find(|child| child.kind() == "identifier")?;
                self.macro_name_defined_value(environment, node_text(name, source))
                    .map(i128::from)
            }
            "parenthesized_expression" => expression.named_child(0).and_then(|child| {
                self.preprocessor_integer_value(
                    child,
                    source,
                    environment,
                    expansion_stack,
                    depth + 1,
                )
            }),
            "unary_expression" => {
                let operator = expression.child_by_field_name("operator")?.kind();
                let argument = expression.child_by_field_name("argument")?;
                let value = self.preprocessor_integer_value(
                    argument,
                    source,
                    environment,
                    expansion_stack,
                    depth + 1,
                )?;
                match operator {
                    "+" => Some(value),
                    "-" => value.checked_neg(),
                    "!" => Some(i128::from(value == 0)),
                    "~" => Some(!value),
                    _ => None,
                }
            }
            "binary_expression" => {
                let left = self.preprocessor_integer_value(
                    expression.child_by_field_name("left")?,
                    source,
                    environment,
                    expansion_stack,
                    depth + 1,
                )?;
                let right = self.preprocessor_integer_value(
                    expression.child_by_field_name("right")?,
                    source,
                    environment,
                    expansion_stack,
                    depth + 1,
                )?;
                match expression.child_by_field_name("operator")?.kind() {
                    "+" => left.checked_add(right),
                    "-" => left.checked_sub(right),
                    "*" => left.checked_mul(right),
                    "/" => left.checked_div(right),
                    "%" => left.checked_rem(right),
                    "<<" => u32::try_from(right)
                        .ok()
                        .and_then(|shift| left.checked_shl(shift)),
                    ">>" => u32::try_from(right)
                        .ok()
                        .and_then(|shift| left.checked_shr(shift)),
                    "<" => Some(i128::from(left < right)),
                    "<=" => Some(i128::from(left <= right)),
                    ">" => Some(i128::from(left > right)),
                    ">=" => Some(i128::from(left >= right)),
                    "==" => Some(i128::from(left == right)),
                    "!=" => Some(i128::from(left != right)),
                    "&" => Some(left & right),
                    "|" => Some(left | right),
                    "^" => Some(left ^ right),
                    "&&" => Some(i128::from(left != 0 && right != 0)),
                    "||" => Some(i128::from(left != 0 || right != 0)),
                    _ => None,
                }
            }
            _ => None,
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
        if self.cpp.prepared_syntax(self.token, file).is_none() {
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
                MacroEvent::Define { name, binding, .. } => {
                    Self::merge_conditional_macro_definition(
                        environment,
                        name,
                        binding,
                        conditional_file,
                        conditional_byte,
                    );
                }
                MacroEvent::Undef { name, .. } => {
                    if environment.binding(name).is_some() {
                        environment.insert(
                            name.clone(),
                            MacroBinding::ambiguous(conditional_file, conditional_byte),
                        );
                    } else {
                        environment.remove_known_undefined(name);
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
                        *binding = MacroBinding::uncertain_from(
                            binding,
                            conditional_file,
                            conditional_byte,
                        );
                    }
                }
            }
        }
    }

    fn merge_conditional_macro_definition(
        environment: &mut MacroEnvironment,
        name: &str,
        possible_binding: &MacroBinding,
        conditional_file: &ProjectFile,
        conditional_byte: usize,
    ) {
        // A conditional include can revisit an already-active guarded header.
        // If the possible branch defines the exact same macro, both outcomes
        // leave the binding unchanged; degrading it to Unknown would discard
        // proof because of an unrelated unresolved macro name (#2092).
        if environment.binding(name).is_some_and(|current| {
            current.definition != MacroDefinition::Unsupported
                && current.definition == possible_binding.definition
        }) {
            return;
        }
        environment.insert(
            name.to_string(),
            MacroBinding::ambiguous(conditional_file, conditional_byte),
        );
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
            self.cpp.prepared_syntax(self.token, file).map_or(
                MacroIncludeProtection::None,
                |prepared| {
                    top_level_macro_include_protection(
                        prepared.tree().root_node(),
                        prepared.source(),
                    )
                },
            )
        })
        .clone()
    }

    fn collect_macro_events(&self, file: &ProjectFile) -> Vec<MacroEvent> {
        let Some(prepared) = self.cpp.prepared_syntax(self.token, file) else {
            return Vec::new();
        };
        let source = prepared.source();
        let mut events = Vec::new();
        let root = prepared.tree().root_node();
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
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
                        conditionals: owning_preprocessor_conditionals(root, node, source),
                    });
                    continue;
                }
                "preproc_include" => {
                    let Some(path) = node.child_by_field_name("path") else {
                        events.push(MacroEvent::Include {
                            targets: Vec::new(),
                            byte: node.start_byte(),
                            conditionals: owning_preprocessor_conditionals(root, node, source),
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
                        conditionals: owning_preprocessor_conditionals(root, node, source),
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
                            conditionals: owning_preprocessor_conditionals(root, node, source),
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
                        self.parser_alias_source_parses
                            .fetch_add(1, Ordering::Relaxed);
                        #[cfg(any(test, feature = "test-support"))]
                        {
                            *self
                                .alias_source_parse_counts
                                .lock()
                                .expect("alias source parse count lock")
                                .entry(visible_file.clone())
                                .or_default() += 1;
                        }
                        aliases_from_prepared_source(self.cpp, self.token, &visible_file)
                            .into_boxed_slice()
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

    pub fn parser_alias_name_may_resolve_to_target(
        &self,
        file: &ProjectFile,
        alias_name: &str,
        target: &CodeUnit,
    ) -> bool {
        let started = std::time::Instant::now();
        self.parser_alias_fallback_calls
            .fetch_add(1, Ordering::Relaxed);
        let mut files = 0usize;
        let matched = match self.visible_source_files_by_root.get(file) {
            None => {
                files = 1;
                self.file_alias_matches(self.cpp, file, alias_name, target)
            }
            Some(visible_files) => visible_files.iter().any(|visible_file| {
                files += 1;
                self.file_alias_matches(self.cpp, visible_file, alias_name, target)
            }),
        };
        self.parser_alias_fallback_files
            .fetch_add(files, Ordering::Relaxed);
        self.parser_alias_fallback_elapsed_micros.fetch_add(
            started.elapsed().as_micros().min(usize::MAX as u128) as usize,
            Ordering::Relaxed,
        );
        matched
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
        // The activation ranges here describe the whole file rather than one
        // reference, so there is no reference guard environment to consult.
        let reference = CallableReferenceContext {
            file,
            position: None,
        };
        for (candidate, candidate_arity) in differing_candidates {
            let declaration_activation = if candidate.source() == file {
                callable_declaration_activation_in_file(analyzer, prepared, candidate, &reference)
            } else {
                cpp.prepared_syntax(self.token, candidate.source())
                    .and_then(|syntax| {
                        callable_declaration_activation_in_file(
                            analyzer,
                            syntax.as_ref(),
                            candidate,
                            &reference,
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
        let activation = find_include_activation(cpp, self.token, file, prepared, donor_source);
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
        static EMPTY: OnceLock<Arc<[ConditionalIncludeProjection]>> = OnceLock::new();
        let cell = self
            .conditional_include_projection_cells
            .lock()
            .expect("C++ conditional include projection cache poisoned")
            .entry(file.clone())
            .or_insert_with(|| Arc::new(PoolSafeMemo::new()))
            .clone();
        let index = cell.get_or_build_pool_independent(|| {
            #[cfg(any(test, feature = "test-support"))]
            self.conditional_include_projection_index_build_count
                .fetch_add(1, Ordering::Relaxed);
            find_conditional_include_projection_index(self.cpp, self.token, file, prepared, &|| {
                #[cfg(any(test, feature = "test-support"))]
                self.conditional_include_projection_state_count
                    .fetch_add(1, Ordering::Relaxed);
            })
        });
        index
            .get(donor_source)
            .cloned()
            .unwrap_or_else(|| Arc::clone(EMPTY.get_or_init(|| Arc::from([]))))
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn conditional_include_projection_work_counts_for_test(&self) -> (usize, usize) {
        (
            self.conditional_include_projection_index_build_count
                .load(Ordering::Relaxed),
            self.conditional_include_projection_state_count
                .load(Ordering::Relaxed),
        )
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn conditional_include_target_state_count_for_test(&self) -> usize {
        self.conditional_include_target_state_count
            .load(Ordering::Relaxed)
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
    pub fn using_work_counts_for_test(&self) -> (usize, usize, usize, usize) {
        (
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

    /// Whether some declaration of `declaration`'s logical symbol is visible at
    /// `reference_byte` in `file`.
    ///
    /// The question is asked of the *logical* symbol, not of the physical unit:
    /// an out-of-line body in a `.cpp` nobody includes is never itself visible,
    /// and it does not have to be - what makes the call legal is the header
    /// declaration that the reference file does include. Reading that relation
    /// through `same_logical_callable` rather than through signature strings is
    /// the same #2010 correction the gates make, and it matters here because
    /// the body and the declaration are exactly the pair that spells one
    /// parameter type two ways.
    pub fn declaration_visible_at(
        &self,
        analyzer: &CppGraphSource<'_>,
        file: &ProjectFile,
        declaration: &CodeUnit,
        reference_byte: usize,
    ) -> bool {
        let reference_guards = OnceCell::new();
        self.visible_identifier_candidates(file, declaration.identifier())
            .filter(|candidate| {
                self.same_logical_callable(analyzer, candidate, declaration)
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
                self.physical_declaration_visible_at(
                    analyzer,
                    file,
                    candidate,
                    reference_byte,
                    &reference_guards,
                )
            })
    }

    /// C forward navigation may bind a call to a later same-file definition.
    /// There is no earlier source declaration to activate in that legacy C
    /// shape, but the call's preprocessor environment must still imply the
    /// definition's requirements. Ordinary C++ and inverse visibility retain
    /// the declaration-order rule in [`Self::declaration_visible_at`].
    pub fn declaration_visible_for_c_forward_call(
        &self,
        analyzer: &CppGraphSource<'_>,
        file: &ProjectFile,
        declaration: &CodeUnit,
        reference_byte: usize,
    ) -> bool {
        if self.declaration_visible_at(analyzer, file, declaration, reference_byte) {
            return true;
        }
        if declaration.source() != file {
            return false;
        }
        let Some(prepared) = self.cpp.prepared_syntax(self.token, file) else {
            return false;
        };
        let reference_guards = prepared
            .tree()
            .root_node()
            .descendant_for_byte_range(reference_byte, reference_byte)
            .and_then(|node| preprocessor_guard_environment(node, prepared.source()));
        declaration_guard_requirements(analyzer, self.cpp, declaration)
            .into_iter()
            .any(|(_, required)| {
                guard_requirements_hold_at_reference(&required, reference_guards.as_ref())
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
            let prepared = self.cpp.prepared_syntax(self.token, file)?;
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
        reference_guards: &OnceCell<Option<HashSet<PreprocessorGuard>>>,
    ) -> bool {
        let Some(prepared) = self.cpp.prepared_syntax(self.token, file) else {
            return false;
        };
        let reference = CallableReferenceContext {
            file,
            position: Some(CallableReferencePosition {
                prepared: prepared.as_ref(),
                byte: reference_byte,
                guards: reference_guards,
            }),
        };
        if declaration.source() == file {
            return callable_declaration_activation_in_file(
                analyzer,
                prepared.as_ref(),
                declaration,
                &reference,
            )
            .or_else(|| {
                self.exhaustive_guard_family_activation(
                    analyzer,
                    prepared.as_ref(),
                    declaration,
                    &reference,
                )
            })
            .is_some_and(|activation| activation < reference_byte);
        }
        let Some(donor_syntax) = self.cpp.prepared_syntax(self.token, declaration.source()) else {
            return false;
        };
        if callable_declaration_activation_in_file(
            analyzer,
            donor_syntax.as_ref(),
            declaration,
            &reference,
        )
        .or_else(|| {
            self.exhaustive_guard_family_activation(
                analyzer,
                donor_syntax.as_ref(),
                declaration,
                &reference,
            )
        })
        .is_none()
        {
            return false;
        }
        declaration_guard_requirements(analyzer, self.cpp, declaration)
            .into_iter()
            .any(|(_, declaration_guards)| {
                self.foreign_declaration_reachable_at_reference(
                    file,
                    prepared.as_ref(),
                    declaration.source(),
                    &declaration_guards,
                    reference.guards(),
                    reference_byte,
                )
            })
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
        let Some(prepared) = self.cpp.prepared_syntax(self.token, file) else {
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
        let Some(prepared) = self.cpp.prepared_syntax(self.token, file) else {
            return false;
        };
        self.include_activation_for_source(self.cpp, file, prepared.as_ref(), candidate.source())
            .is_some_and(|activation| activation <= reference_byte)
    }

    /// The preprocessor facts the build proves for a reference sited in
    /// `file` (#2011).
    ///
    /// Every `-D` that survives its command's `-D`/`-U` ordering is a positive
    /// `Defined` fact, and a fact holds only when every compile configuration
    /// that governs the file agrees on it (intersection). The facts are
    /// strictly additive to the reference's active guard set: they can prove a
    /// required guard, but the guard check itself is never weakened and no
    /// implication is ever inferred from source text.
    ///
    /// A file with its own database entry answers from that entry alone
    /// (phase 1). A header takes its context from the translation units whose
    /// include closure reaches it, intersected across all of them (phase 2):
    /// the header is compiled once per including TU, so a fact holds for a
    /// header-sited reference only when every one of those compilations
    /// proves it. A reaching TU the database does not cover proves nothing,
    /// which empties the intersection. A file nothing covers or reaches has
    /// no facts and every check runs on source structure alone.
    pub fn compile_proven_guards(&self, file: &ProjectFile) -> Arc<HashSet<PreprocessorGuard>> {
        if let Some(cached) = self
            .compile_proven_guard_cells
            .lock()
            .expect("C++ compile-proven guard cache poisoned")
            .get(file)
        {
            return Arc::clone(cached);
        }
        let names = match context_fact_names(self.cpp.compile_contexts_for(file)) {
            Some(names) => names,
            None => {
                let mut translation_units = self.cpp.reaching_translation_units(file).into_iter();
                let seed = translation_units.next().and_then(|translation_unit| {
                    context_fact_names(self.cpp.compile_contexts_for(&translation_unit))
                });
                match seed {
                    None => HashSet::default(),
                    Some(mut names) => {
                        for translation_unit in translation_units {
                            let Some(reached) = context_fact_names(
                                self.cpp.compile_contexts_for(&translation_unit),
                            ) else {
                                names.clear();
                                break;
                            };
                            names.retain(|name| reached.contains(name));
                            if names.is_empty() {
                                break;
                            }
                        }
                        names
                    }
                }
            }
        };
        let proven = Arc::new(
            names
                .into_iter()
                .map(PreprocessorGuard::Defined)
                .collect::<HashSet<_>>(),
        );
        self.compile_proven_guard_cells
            .lock()
            .expect("C++ compile-proven guard cache poisoned")
            .insert(file.clone(), Arc::clone(&proven));
        proven
    }

    /// Whether no compile data covers the compilations of `file`: it has no
    /// database entry of its own, and either nothing reaches it or some
    /// translation unit that reaches it has no entry. This is the state a
    /// regenerated `compile_commands.json` could decide; data that is present
    /// for every governing compilation but does not prove a guard is a
    /// decided conservative miss, not this state.
    fn compile_context_is_absent(&self, file: &ProjectFile) -> bool {
        if !self.cpp.compile_contexts_for(file).is_empty() {
            return false;
        }
        let translation_units = self.cpp.reaching_translation_units(file);
        translation_units.is_empty()
            || translation_units
                .iter()
                .any(|translation_unit| self.cpp.compile_contexts_for(translation_unit).is_empty())
    }

    /// Whether a lookup miss for `identifier` in `file` is explainable by
    /// missing compile context (#2011): some same-name declaration is
    /// reachable through a conditional include whose required guards neither
    /// contradict the reference's active guards nor follow from them, and the
    /// translation unit has no compile-commands entry that could decide the
    /// question. Callers surface this as an explicit "requires compile
    /// context" incompleteness instead of an indistinguishable miss.
    ///
    /// A structurally disproven declaration (contradicting guards) and a TU
    /// whose compile context exists but does not prove the guard both answer
    /// `false`: those misses are decided, not incomplete.
    pub fn miss_requires_compile_context(
        &self,
        file: &ProjectFile,
        identifier: &str,
        reference: Node<'_>,
    ) -> bool {
        if !self.compile_context_is_absent(file) {
            return false;
        }
        let Some(prepared) = self.cpp.prepared_syntax(self.token, file) else {
            return false;
        };
        let reference_guards = preprocessor_guard_environment(reference, prepared.source());
        let reference_byte = reference.start_byte();
        let mut sources = self
            .visible_identifier_candidates(file, identifier)
            .map(CodeUnit::source)
            .filter(|source| *source != file)
            .collect::<Vec<_>>();
        sources.sort();
        sources.dedup();
        sources.into_iter().any(|declaration_source| {
            self.conditional_include_projections_for_source(
                file,
                prepared.as_ref(),
                declaration_source,
            )
            .iter()
            .any(|projection| {
                projection.activation_byte <= reference_byte
                    && !guard_requirements_hold_at_reference(
                        &projection.required_guards,
                        reference_guards.as_ref(),
                    )
                    && guards_compatible_at_reference(
                        &projection.required_guards,
                        reference_guards.as_ref(),
                    )
            })
        })
    }

    /// Decide whether a declaration that lives in another file reaches a
    /// reference in `file`.
    ///
    /// An external header selects its declaration branch before the reference
    /// file is parsed. Require compatible reference guards, but do not test
    /// the header's guard expression for stability in the reference file: a
    /// `.c` translation unit can never satisfy the `#ifdef __cplusplus` that
    /// wraps every declaration of a portable C header, and demanding it would
    /// hide the whole header. Guards that the reference file imposes on its
    /// own `#include` still have to hold, and still have to be stable.
    fn foreign_declaration_reachable_at_reference(
        &self,
        file: &ProjectFile,
        prepared: &PreparedSyntaxTree,
        declaration_source: &ProjectFile,
        declaration_guards: &HashSet<PreprocessorGuard>,
        reference_guards: Option<&HashSet<PreprocessorGuard>>,
        reference_byte: usize,
    ) -> bool {
        // The translation unit's build-proven defines join the reference's
        // active guard set (#2011): a conditional include like the nng
        // `NNG_PLATFORM_POSIX` chain is provable only by the compile command.
        // A reference whose own environment is unknown stays unknown -- the
        // facts extend an environment, they never invent one.
        let proven = self.compile_proven_guards(file);
        let augmented;
        let reference_guards = match reference_guards {
            Some(active) if !proven.is_empty() => {
                augmented = active.union(&proven).cloned().collect();
                Some(&augmented)
            }
            other => other,
        };
        if !guards_compatible_at_reference(declaration_guards, reference_guards) {
            return false;
        }
        if self
            .include_activation_for_source(self.cpp, file, prepared, declaration_source)
            .is_some_and(|activation| activation <= reference_byte)
        {
            return true;
        }
        let projections =
            self.conditional_include_projections_for_source(file, prepared, declaration_source);
        if std::env::var_os("BIFROST_CPP_VISIBILITY_STATS").is_some() {
            eprintln!(
                "BIFROST_CPP_TYPE_VISIBILITY_STATS phase=filtered_projection source={} declaration_guards={} proven_guards={} projections={}",
                declaration_source.rel_path().display(),
                declaration_guards.len(),
                proven.len(),
                projections.len(),
            );
        }
        projections.iter().any(|projection| {
            projection.activation_byte <= reference_byte
                && guard_requirements_hold_at_reference(
                    &projection.required_guards,
                    reference_guards,
                )
                && self.preprocessor_guards_stable_between(
                    file,
                    projection.activation_byte,
                    reference_byte,
                    &projection.required_guards,
                )
        })
    }

    fn foreign_declaration_may_be_reachable_from_raw_guards(
        &self,
        file: &ProjectFile,
        prepared: &PreparedSyntaxTree,
        declaration_source: &ProjectFile,
        declaration_guards: &HashSet<PreprocessorGuard>,
        reference_guards: Option<&HashSet<PreprocessorGuard>>,
        reference_byte: usize,
    ) -> bool {
        let proven = self.compile_proven_guards(file);
        let augmented;
        let reference_guards = match reference_guards {
            Some(active) if !proven.is_empty() => {
                augmented = active.union(&proven).cloned().collect();
                Some(&augmented)
            }
            other => other,
        };
        if !guards_compatible_at_reference(declaration_guards, reference_guards) {
            return false;
        }
        if self
            .include_activation_for_source(self.cpp, file, prepared, declaration_source)
            .is_some_and(|activation| activation <= reference_byte)
        {
            return true;
        }
        let reachable = find_conditional_include_projection_for_source(
            self.cpp,
            self.token,
            file,
            prepared,
            declaration_source,
            reference_guards,
            reference_byte,
            &|| {
                #[cfg(any(test, feature = "test-support"))]
                self.conditional_include_target_state_count
                    .fetch_add(1, Ordering::Relaxed);
            },
        );
        if std::env::var_os("BIFROST_CPP_VISIBILITY_STATS").is_some() {
            eprintln!(
                "BIFROST_CPP_TYPE_VISIBILITY_STATS phase=raw_projection source={} declaration_guards={} proven_guards={} raw_guards={} reachable={reachable}",
                declaration_source.rel_path().display(),
                declaration_guards.len(),
                proven.len(),
                reference_guards.map_or(0, HashSet::len),
            );
        }
        reachable
    }

    fn foreign_declaration_reachable_from_compile_proven_guards(
        &self,
        file: &ProjectFile,
        prepared: &PreparedSyntaxTree,
        declaration_source: &ProjectFile,
        declaration_guards: &HashSet<PreprocessorGuard>,
        reference_byte: usize,
    ) -> bool {
        let proven = self.compile_proven_guards(file);
        if proven.is_empty()
            || !guards_compatible_at_reference(declaration_guards, Some(proven.as_ref()))
        {
            return false;
        }
        let projections =
            self.conditional_include_projections_for_source(file, prepared, declaration_source);
        if std::env::var_os("BIFROST_CPP_VISIBILITY_STATS").is_some() {
            eprintln!(
                "BIFROST_CPP_TYPE_VISIBILITY_STATS phase=compile_proven_projection source={} declaration_guards={} proven_guards={} projections={}",
                declaration_source.rel_path().display(),
                declaration_guards.len(),
                proven.len(),
                projections.len(),
            );
        }
        projections.iter().any(|projection| {
            projection.activation_byte <= reference_byte
                    && guard_requirements_hold_at_reference(
                        &projection.required_guards,
                        Some(proven.as_ref()),
                    )
                    // Build facts hold at translation-unit entry. A source
                    // `#undef` or an earlier include may invalidate one before
                    // this conditional include is reached; mutations after the
                    // include cannot revoke declarations it already supplied.
                    && self.preprocessor_guards_stable_between(
                        file,
                        0,
                        projection.activation_byte,
                        &projection.required_guards,
                    )
        })
    }

    pub fn external_type_candidate_visible_in_context(
        &self,
        analyzer: &CppGraphSource<'_>,
        file: &ProjectFile,
        candidate: &CodeUnit,
        reference: Node<'_>,
    ) -> bool {
        let report_stats = std::env::var_os("BIFROST_CPP_VISIBILITY_STATS").is_some();
        if report_stats {
            eprintln!(
                "BIFROST_CPP_TYPE_VISIBILITY_STATS phase=candidate status=started fqn={} candidate_source={} reference_file={} reference_byte={}",
                candidate.fq_name(),
                candidate.source().rel_path().display(),
                file.rel_path().display(),
                reference.start_byte(),
            );
        }
        let Some(prepared) = self.cpp.prepared_syntax(self.token, file) else {
            return false;
        };
        let raw_reference_guards = preprocessor_guard_environment(reference, prepared.source());
        let reference_guards = OnceCell::new();
        let reference_guards_at_site = || {
            reference_guards.get_or_init(|| {
                let started = Instant::now();
                if report_stats {
                    eprintln!(
                        "BIFROST_CPP_TYPE_VISIBILITY_STATS phase=macro_environment status=started file={} reference_byte={} raw_guards={}",
                        file.rel_path().display(),
                        reference.start_byte(),
                        raw_reference_guards.as_ref().map_or(0, HashSet::len),
                    );
                }
                let macro_environment = self.macro_environment(file, reference.start_byte());
                let filtered = raw_reference_guards
                    .clone()
                    .filter(|guards| macro_environment.guard_requirements_may_hold(guards));
                if report_stats {
                    eprintln!(
                        "BIFROST_CPP_TYPE_VISIBILITY_STATS phase=macro_environment status=completed retained={} elapsed_ms={}",
                        filtered.is_some(),
                        started.elapsed().as_millis(),
                    );
                }
                filtered
            })
        };

        let peers = self
            .visible_identifier_candidates(file, candidate.identifier())
            .filter(|peer| same_logical_symbol(candidate, peer))
            .collect::<Vec<_>>();
        if report_stats {
            let peer_sources = peers
                .iter()
                .map(|peer| peer.source().rel_path().display().to_string())
                .collect::<Vec<_>>();
            eprintln!(
                "BIFROST_CPP_TYPE_VISIBILITY_STATS phase=peers fqn={} sources={peer_sources:?}",
                candidate.fq_name(),
            );
        }
        let directly_visible_without_reference_environment = peers.iter().any(|peer| {
            declaration_guard_requirements(analyzer, self.cpp, peer)
                .into_iter()
                .any(|(declaration_byte, declaration_guards)| {
                    if peer.source() == file {
                        let visible = declaration_byte < reference.start_byte()
                            && declaration_guards.is_empty();
                        if report_stats {
                            eprintln!(
                                "BIFROST_CPP_TYPE_VISIBILITY_STATS phase=direct_peer source={} declaration_guards={} same_file=true visible={visible}",
                                peer.source().rel_path().display(),
                                declaration_guards.len(),
                            );
                        }
                        return visible;
                    }
                    let direct = declaration_guards.is_empty()
                        && self
                            .include_activation_for_source(
                                self.cpp,
                                file,
                                prepared.as_ref(),
                                peer.source(),
                            )
                            .is_some_and(|activation| activation <= reference.start_byte());
                    let compile_proven = !direct
                        && self.foreign_declaration_reachable_from_compile_proven_guards(
                            file,
                            prepared.as_ref(),
                            peer.source(),
                            &declaration_guards,
                            reference.start_byte(),
                        );
                    if report_stats {
                        eprintln!(
                            "BIFROST_CPP_TYPE_VISIBILITY_STATS phase=direct_peer source={} declaration_guards={} same_file=false direct={direct} compile_proven={compile_proven}",
                            peer.source().rel_path().display(),
                            declaration_guards.len(),
                        );
                    }
                    direct || compile_proven
                })
        });
        if directly_visible_without_reference_environment {
            if report_stats {
                eprintln!(
                    "BIFROST_CPP_TYPE_VISIBILITY_STATS phase=candidate status=completed outcome=direct_or_compile_proven fqn={}",
                    candidate.fq_name(),
                );
            }
            return true;
        }
        let directly_visible = peers.iter().any(|peer| {
            declaration_guard_requirements(analyzer, self.cpp, peer)
                .into_iter()
                .any(|(declaration_byte, declaration_guards)| {
                    if peer.source() == file {
                        if declaration_byte >= reference.start_byte() {
                            return false;
                        }
                        if !guard_requirements_hold_at_reference(
                            &declaration_guards,
                            raw_reference_guards.as_ref(),
                        ) {
                            return false;
                        }
                        return guard_requirements_hold_at_reference(
                            &declaration_guards,
                            reference_guards_at_site().as_ref(),
                        ) && self.preprocessor_guards_stable_between(
                            file,
                            declaration_byte,
                            reference.start_byte(),
                            &declaration_guards,
                        );
                    }
                    let raw_feasible = self.foreign_declaration_may_be_reachable_from_raw_guards(
                        file,
                        prepared.as_ref(),
                        peer.source(),
                        &declaration_guards,
                        raw_reference_guards.as_ref(),
                        reference.start_byte(),
                    );
                    if report_stats {
                        eprintln!(
                            "BIFROST_CPP_TYPE_VISIBILITY_STATS phase=raw_feasibility source={} declaration_guards={} feasible={raw_feasible}",
                            peer.source().rel_path().display(),
                            declaration_guards.len(),
                        );
                    }
                    if !raw_feasible {
                        return false;
                    }
                    self.foreign_declaration_reachable_at_reference(
                        file,
                        prepared.as_ref(),
                        peer.source(),
                        &declaration_guards,
                        reference_guards_at_site().as_ref(),
                        reference.start_byte(),
                    )
                })
        });
        if directly_visible {
            if report_stats {
                eprintln!(
                    "BIFROST_CPP_TYPE_VISIBILITY_STATS phase=candidate status=completed outcome=filtered_reference fqn={}",
                    candidate.fq_name(),
                );
            }
            return true;
        }
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
        let complementary_family =
            self.complementary_same_fqn_type_declarations(analyzer, &complementary, candidate);
        let raw_candidate_branch_compatible = complementary_family
            && raw_reference_guards.as_ref().is_some_and(|active| {
                declaration_guard_requirements(analyzer, self.cpp, candidate)
                    .iter()
                    .any(|(_, required)| merge_preprocessor_guards(required, active).is_some())
            });
        if report_stats {
            eprintln!(
                "BIFROST_CPP_TYPE_VISIBILITY_STATS phase=complementary fqn={} candidates={} family={} raw_compatible={}",
                candidate.fq_name(),
                complementary.len(),
                complementary_family,
                raw_candidate_branch_compatible,
            );
        }
        let candidate_branch_compatible = raw_candidate_branch_compatible
            && reference_guards_at_site().as_ref().is_some_and(|active| {
                declaration_guard_requirements(analyzer, self.cpp, candidate)
                    .iter()
                    .any(|(_, required)| merge_preprocessor_guards(required, active).is_some())
            });
        let complementary_visible = candidate_branch_compatible
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
        if report_stats {
            eprintln!(
                "BIFROST_CPP_TYPE_VISIBILITY_STATS phase=candidate status=completed outcome={} fqn={}",
                if complementary_visible {
                    "complementary"
                } else {
                    "missing"
                },
                candidate.fq_name(),
            );
        }
        complementary_visible
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

        let Some(prepared) = self.cpp.prepared_syntax(self.token, file) else {
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
            guards_compatible_at_reference(target_guards, Some(&reference_guards))
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
        let Some(prepared) = self.cpp.prepared_syntax(self.token, file) else {
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
                        self.foreign_declaration_reachable_at_reference(
                            file,
                            prepared.as_ref(),
                            peer.source(),
                            &declaration_guards,
                            reference_guards.as_ref(),
                            reference.start_byte(),
                        )
                    })
            })
    }

    /// Whether a same-file callable declaration is nameable from `reference`
    /// after deliberately relaxing declaration-before-reference ordering.
    ///
    /// Ordinary lookup still requires an earlier declaration. Definition
    /// navigation for incomplete C translation units may recover a later
    /// definition, but only when it is at file scope and its preprocessor
    /// requirements hold at the call (#2404).
    pub fn same_file_callable_guard_compatible_ignoring_order(
        &self,
        analyzer: &CppGraphSource<'_>,
        file: &ProjectFile,
        candidate: &CodeUnit,
        reference: Node<'_>,
    ) -> bool {
        if candidate.source() != file || !candidate.is_callable() {
            return false;
        }
        let Some(prepared) = self.cpp.prepared_syntax(self.token, file) else {
            return false;
        };
        let guards = OnceCell::new();
        let context = CallableReferenceContext {
            file,
            position: Some(CallableReferencePosition {
                prepared: prepared.as_ref(),
                byte: reference.start_byte(),
                guards: &guards,
            }),
        };
        nameable_callable_declaration_nodes(analyzer, prepared.as_ref(), candidate)
            .into_iter()
            .any(|declaration| {
                callable_preprocessor_context_is_visible_for_reference(
                    declaration,
                    prepared.source(),
                    &context,
                )
            })
    }

    pub fn type_candidate_may_be_visible_before_reference(
        &self,
        analyzer: &CppGraphSource<'_>,
        file: &ProjectFile,
        candidate: &CodeUnit,
        reference_byte: usize,
    ) -> bool {
        let Some(prepared) = self.cpp.prepared_syntax(self.token, file) else {
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

    /// Mirror forward navigation's visible-name fallback for a bare parameter
    /// type after lexical owner and inheritance lookup is exhausted.
    ///
    /// Generated or otherwise unindexed base classes can hide the alias that
    /// makes a parameter type valid C++. Accept the fallback only when every
    /// include-visible class or alias with that spelling canonicalizes to one
    /// logical type. A shadowing local type resolves lexically before this
    /// path, while distinct visible types keep the result ambiguous.
    pub fn unique_visible_parameter_type_fallback(
        &self,
        analyzer: &CppGraphSource<'_>,
        file: &ProjectFile,
        node: Node<'_>,
        source: &str,
    ) -> Option<CodeUnit> {
        if node.kind() != "type_identifier" || !is_parameter_type_reference(node) {
            return None;
        }
        let name = node_text(node, source);
        let candidates = self
            .visible_identifier_candidates(file, name)
            .filter(|candidate| candidate.is_class() || declared_type_alias(analyzer, candidate))
            .filter(|candidate| {
                self.external_type_candidate_visible_in_context(analyzer, file, candidate, node)
            })
            .collect::<Vec<_>>();
        self.unique_canonical_type_candidate(analyzer, file, &candidates)
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
                (metadata.is_primary() && self.is_visible(file, unit)).then_some((unit, metadata))
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
            if metadata.is_primary() || !self.is_visible(file, unit) {
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

        let mut saw_shape_candidate = false;
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
        // One candidate goes in, so a failure here is never "choose one of
        // these": it is the alias chain leaving the index, which must answer
        // missing rather than ambiguous (#1828).
        match self.resolve_type_candidates(analyzer, file, &candidates, resolution) {
            Ok(unit) => LexicalTypeResolution::Resolved {
                unit,
                components: target_components.to_vec(),
                candidates: vec![target.clone()],
            },
            Err(failure) => failure.lexical_resolution(),
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
        for qualified in lexical_component_tiers(components, global, lexical_scope) {
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
                if !global && components.len() == 1 {
                    match self.resolve_inherited_type_for_lexical_scope(
                        analyzer,
                        file,
                        &qualified[..prefix_len],
                        &components[0],
                        resolution,
                    ) {
                        LexicalTypeResolution::Missing => {}
                        inherited => return inherited,
                    }
                }
                continue;
            }
            let unit = match self.resolve_type_candidates(analyzer, file, &candidates, resolution) {
                Ok(unit) => unit,
                Err(failure) => return failure.lexical_resolution(),
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
        let resolution = match self.resolve_type_candidates(analyzer, file, &matches, resolution) {
            Ok(unit) => LexicalTypeResolution::Resolved {
                unit,
                components: owner_components,
                candidates: matches.into_iter().cloned().collect(),
            },
            Err(failure) => failure.lexical_resolution(),
        };
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
        // A visible forward declaration and the physical class definition share
        // one FQN, but only the definition owns hierarchy facts. When lookup is
        // physically inside that definition, do not let an earlier header
        // forward declaration erase its base edges (#2240).
        let physical_owner_candidates = owner_candidates
            .iter()
            .copied()
            .filter(|candidate| candidate.source() == file)
            .collect::<Vec<_>>();
        let lexical_owner_candidates = if physical_owner_candidates.is_empty() {
            owner_candidates
        } else {
            physical_owner_candidates
        };
        let Some(lexical_owner) = unique_logical_type_candidate(lexical_owner_candidates) else {
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
                let unit =
                    match self.resolve_type_candidates(analyzer, file, &candidates, resolution) {
                        Ok(unit) => unit,
                        Err(failure) => return failure.lexical_resolution(),
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

    /// Resolve a base class through its injected class name at the nearest
    /// inheritance tier. Distinct same-named bases at that tier are ambiguous.
    ///
    /// A base whose canonical full definition cannot be pinned from `file` -
    /// a forward declaration the include closure completes with two different
    /// full definitions, or an alias chain that leaves the index - stops the
    /// walk only when that base is spelled `injected_name`. The mem-initializer
    /// names a base by that base's own injected class name, so a base spelled
    /// differently can never be the one it names, whichever definition it would
    /// have turned out to be; aborting the level on its account instead loses
    /// the sibling base that *is* named (#2543). A base that is spelled
    /// `injected_name` still fails closed, because choosing a deeper same-named
    /// ancestor over it would bind the initializer to the wrong constructor.
    /// The skipped base carries its own ancestors out of the walk with it: with
    /// no canonical unit, the repeated-base accounting below cannot tell one
    /// inherited path through it from two.
    pub fn inherited_injected_class_owner(
        &self,
        analyzer: &CppGraphSource<'_>,
        file: &ProjectFile,
        enclosing_owner: &CodeUnit,
        injected_name: &str,
    ) -> Option<CodeUnit> {
        let hierarchy = analyzer.type_hierarchy_provider()?;
        let mut frontier = hierarchy.get_direct_ancestors(enclosing_owner);
        let mut propagated_counts: HashMap<CodeUnit, u8> = HashMap::default();
        while !frontier.is_empty() {
            let mut level_matches = Vec::new();
            let mut next_frontier = Vec::new();
            for raw_owner in frontier {
                let Some(owner) = self.canonical_visible_full_type_unit(analyzer, file, &raw_owner)
                else {
                    if raw_owner.identifier() == injected_name {
                        return None;
                    }
                    continue;
                };
                let propagated = propagated_counts.entry(owner.clone()).or_default();
                if *propagated == 2 {
                    continue;
                }
                *propagated += 1;
                if owner.identifier() == injected_name {
                    level_matches.push(owner.clone());
                }
                next_frontier.extend(hierarchy.get_direct_ancestors(&owner));
            }
            match level_matches.as_slice() {
                [owner] => return Some(owner.clone()),
                [_, ..] => return None,
                [] => {}
            }
            frontier = next_frontier;
        }
        None
    }

    /// The one type the candidates name under `resolution`, or why they do not
    /// name one. The two preserving modes only ever reject candidates that
    /// disagree with each other, which is ambiguity; canonicalization can also
    /// fail because the alias chain leaves the index (#1828).
    fn resolve_type_candidates(
        &self,
        analyzer: &CppGraphSource<'_>,
        file: &ProjectFile,
        candidates: &[&CodeUnit],
        resolution: TypeCandidateResolution<'_>,
    ) -> Result<CodeUnit, TypeCandidateFailure> {
        match resolution {
            TypeCandidateResolution::Canonical => {
                self.canonical_type_candidate_resolution(analyzer, file, candidates)
            }
            TypeCandidateResolution::PreserveAlias => {
                // A generated index can retain identical alias spellings from
                // mutually exclusive headers. When the reference file
                // physically reaches exactly one of those source declarations,
                // include closure is the structured evidence that selects it;
                // treating the two source spellings as an overload set makes a
                // reachable alias appear ambiguous (#1844).
                let same_fqn_alias_family = candidates.len() > 1
                    && candidates.iter().all(|candidate| {
                        declared_type_alias(analyzer, candidate)
                            && same_logical_symbol(candidates[0], candidate)
                    })
                    && candidates
                        .iter()
                        .any(|candidate| candidate.source() != candidates[0].source());
                if same_fqn_alias_family {
                    let physically_visible = candidates
                        .iter()
                        .copied()
                        .filter(|candidate| self.is_physically_visible(file, candidate))
                        .collect::<Vec<_>>();
                    // The family is one logical declaration only when the
                    // reachable spellings agree. Two same-FQN aliases whose
                    // written targets differ (`using Choice = Canonical;` in
                    // one header, `using Choice = ::Canonical;` in another)
                    // are a genuine conflict, and choosing the first indexed
                    // one silently binds the reference to an arbitrary owner
                    // (#2398). Collapse only a single reachable declaration
                    // or reachable declarations with one structured target;
                    // everything else stays ambiguous below.
                    let one_structured_target = physically_visible.len() > 1
                        && physically_visible.iter().skip(1).all(|candidate| {
                            let target = self.structured_alias_target(analyzer, candidate);
                            target.is_some()
                                && target
                                    == self.structured_alias_target(analyzer, physically_visible[0])
                        });
                    if physically_visible.len() == 1 || one_structured_target {
                        return Ok(physically_visible[0].clone());
                    }
                }
                unique_type_candidate_preserving_alias(analyzer, candidates)
                    .ok_or(TypeCandidateFailure::Ambiguous)
            }
            TypeCandidateResolution::PreserveTarget(target) => self
                .unique_type_candidate_preserving_target(analyzer, file, candidates, target)
                .ok_or(TypeCandidateFailure::Ambiguous),
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
        self.canonical_type_resolution(analyzer, visible_from, unit)
            .ok()
    }

    /// Follow an alias only when it is visible at `reference`.
    ///
    /// The consumer need not spell the alias target. In particular, a
    /// conditional include can make `PublicPtr` visible at the reference while
    /// ordinary physical-include visibility is false. Prove the public alias
    /// with the reference's guard environment, then use the existing structured
    /// alias-chain resolver over the consumer's bounded declaration index.
    pub fn canonical_type_unit_in_context(
        &self,
        analyzer: &CppGraphSource<'_>,
        visible_from: &ProjectFile,
        reference: Node<'_>,
        unit: &CodeUnit,
    ) -> Option<CodeUnit> {
        if !self.external_type_candidate_visible_in_context(analyzer, visible_from, unit, reference)
        {
            return None;
        }
        self.canonical_type_resolution(analyzer, visible_from, unit)
            .ok()
    }

    /// Follow `unit`'s alias chain to the class it names, or report why the
    /// chain does not end at one indexed class.
    ///
    /// A chain that leaves the index - an alias to a template parameter, to a
    /// standard-library type, or to any other declaration the workspace does
    /// not hold - is `Unresolvable`, not `Ambiguous` (#1828). So is a cycle:
    /// there is still nothing to choose between.
    fn canonical_type_resolution(
        &self,
        analyzer: &CppGraphSource<'_>,
        visible_from: &ProjectFile,
        unit: &CodeUnit,
    ) -> Result<CodeUnit, TypeCandidateFailure> {
        let mut current = unit.clone();
        let mut seen_aliases = HashSet::default();
        loop {
            let Some(target) = self.structured_alias_target(analyzer, &current) else {
                return current
                    .is_class()
                    .then_some(current)
                    .ok_or(TypeCandidateFailure::Unresolvable);
            };
            if matches!(target, StructuredAliasTarget::Builtin) {
                return current
                    .is_class()
                    .then_some(current)
                    .ok_or(TypeCandidateFailure::Unresolvable);
            }
            if !seen_aliases.insert(current.clone()) {
                return Err(TypeCandidateFailure::Unresolvable);
            }
            current = self.structured_alias_target_resolution(visible_from, &current, &target)?;
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
        self.structured_alias_target_resolution(visible_from, declaration, target)
            .ok()
    }

    fn structured_alias_target_resolution(
        &self,
        visible_from: &ProjectFile,
        declaration: &CodeUnit,
        target: &StructuredAliasTarget,
    ) -> Result<CodeUnit, TypeCandidateFailure> {
        let primary =
            self.structured_alias_primary_resolution(visible_from, declaration, target)?;
        let StructuredAliasTarget::Named { arguments, .. } = target else {
            return Err(TypeCandidateFailure::Unresolvable);
        };
        match arguments {
            Some(arguments) => self
                .resolve_template_arguments(visible_from, primary, arguments)
                .map_err(|error| match error {
                    CppTemplateResolutionError::AmbiguousSpecialization { .. } => {
                        TypeCandidateFailure::Ambiguous
                    }
                    _ => TypeCandidateFailure::Unresolvable,
                }),
            None => Ok(primary),
        }
    }

    fn resolve_structured_alias_primary(
        &self,
        visible_from: &ProjectFile,
        declaration: &CodeUnit,
        target: &StructuredAliasTarget,
    ) -> Option<CodeUnit> {
        self.structured_alias_primary_resolution(visible_from, declaration, target)
            .ok()
    }

    fn structured_alias_primary_resolution(
        &self,
        visible_from: &ProjectFile,
        declaration: &CodeUnit,
        target: &StructuredAliasTarget,
    ) -> Result<CodeUnit, TypeCandidateFailure> {
        let StructuredAliasTarget::Named {
            components, global, ..
        } = target
        else {
            return Err(TypeCandidateFailure::Unresolvable);
        };
        let qualified = components.join("::");
        let candidates = if *global {
            // `::A::B` anchors at the root scope, so a candidate whose
            // canonical path merely ends with the spelled components does not
            // qualify. Without this filter a global `::Canonical` target also
            // collects `alpha::Canonical`, the lookup reports a false
            // ambiguity, and the alias arm silently drops out of its
            // conflicting family instead of proving the conflict (#2398).
            let mut candidates = self.type_candidates(visible_from, &qualified);
            candidates.retain(|candidate| canonical_cpp_scope_components(candidate) == *components);
            candidates
        } else {
            self.type_candidates_for_declaration(visible_from, declaration, &qualified)
        };
        logical_type_candidate(candidates)
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

    /// Return true when a class-owned alias names the requested type as one
    /// structured qualifier in its target path.
    ///
    /// A dependent target such as `Primary<T>::Type` cannot resolve to one
    /// indexed class. Forward lookup can still retain `Primary` as its bounded
    /// canonical identity. Inverse lookup needs the same evidence when later
    /// references use only the alias spelling.
    pub fn structured_class_alias_path_preserves_target(
        &self,
        analyzer: &CppGraphSource<'_>,
        visible_from: &ProjectFile,
        alias: &CodeUnit,
        target: &CodeUnit,
    ) -> bool {
        let Some(owner) = type_owner_of(analyzer, alias).filter(CodeUnit::is_class) else {
            return false;
        };
        let Some(StructuredAliasTarget::Named {
            components, global, ..
        }) = self.structured_alias_target(analyzer, alias)
        else {
            return false;
        };
        let lexical_scope = canonical_cpp_scope_components(&owner);
        (1..components.len()).rev().any(|component_count| {
            matches!(
                self.resolve_type_components_lexically_for_target(
                    analyzer,
                    visible_from,
                    &components[..component_count],
                    global,
                    &lexical_scope,
                    target,
                ),
                LexicalTypeResolution::Resolved {
                    ref unit,
                    ref candidates,
                    ..
                } if same_visible_symbol(unit, target)
                    || self.same_template_member_identity(analyzer, unit, target)
                    || candidates.iter().any(|candidate| {
                        same_visible_symbol(candidate, target)
                            || self.same_template_member_identity(analyzer, candidate, target)
                    })
            )
        })
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
        let Some(prepared) = self.cpp.prepared_syntax(self.token, target.source()) else {
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
            .is_some_and(CppTemplateMetadata::is_primary)
    }

    pub fn is_template_specialization(&self, unit: &CodeUnit) -> bool {
        self.cpp_template_metadata
            .get(unit)
            .is_some_and(CppTemplateMetadata::is_specialization)
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
        self.canonical_type_candidate_resolution(analyzer, visible_from, candidates)
            .ok()
    }

    fn canonical_type_candidate_resolution(
        &self,
        analyzer: &CppGraphSource<'_>,
        visible_from: &ProjectFile,
        candidates: &[&CodeUnit],
    ) -> Result<CodeUnit, TypeCandidateFailure> {
        let mut canonical = Vec::new();
        for candidate in candidates {
            let resolved = self.canonical_type_resolution(analyzer, visible_from, candidate)?;
            if canonical
                .iter()
                .any(|existing| same_visible_symbol(existing, &resolved))
            {
                continue;
            }
            if let Some(existing) = canonical.iter_mut().find(|existing| {
                self.compatible_primary_template_redeclarations(existing, &resolved)
            }) {
                // A forward declaration and its full primary-template
                // definition are one C++ type even when they live in
                // different headers and alpha-rename their parameters. The
                // target-preserving path already reconciles this family; do
                // the same for ordinary canonical lookup so an out-of-line
                // member's lexical owner is not made ambiguous by its own
                // forward declaration. Retain the strongest physical
                // declaration for later owner/range queries.
                if matches!(
                    (
                        cpp_class_declaration_strength(analyzer, existing),
                        cpp_class_declaration_strength(analyzer, &resolved),
                    ),
                    (
                        CppClassDeclarationStrength::Forward | CppClassDeclarationStrength::Unknown,
                        CppClassDeclarationStrength::Full,
                    ) | (
                        CppClassDeclarationStrength::Unknown,
                        CppClassDeclarationStrength::Forward,
                    )
                ) {
                    *existing = resolved;
                }
                continue;
            }
            canonical.push(resolved);
            if canonical.len() > 1 {
                return Err(TypeCandidateFailure::Ambiguous);
            }
        }
        canonical.pop().ok_or(TypeCandidateFailure::Unresolvable)
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
            // An ifdef branch that aliases an unindexed system type (for
            // example `typedef pthread_mutex_t k5_os_mutex`) cannot be
            // canonicalized. That branch does not name `target`. Dropping it
            // keeps the branch that does. Failing the whole family here would
            // deny every usage of the reachable spelling (#2368).
            let Some(resolved) =
                self.type_candidate_preserving_target(analyzer, visible_from, candidate, target)
            else {
                continue;
            };
            if resolved_candidates
                .iter()
                .any(|existing| same_visible_symbol(existing, &resolved))
            {
                continue;
            }
            resolved_candidates.push(resolved);
        }
        match resolved_candidates.as_slice() {
            [] => None,
            [single] => Some(single.clone()),
            // The branches disagree about what the name aliases. When they are
            // spellings of one entity (#1845) that disagreement is a build
            // configuration, not a choice between types, so it must not deny
            // the requested target its reference.
            _ => self
                .same_fqn_type_spelling_for_target(analyzer, visible_from, candidates, target)
                .map(|_| target.clone()),
        }
    }

    /// The declaration a same-file same-FQN family stands for when a reference
    /// names `target`, or `None` when the candidates are not one family or the
    /// family does not name `target`.
    ///
    /// A translation unit cannot hold two different types under one qualified
    /// name, so several same-kind declarations of one FQN in one file are
    /// alternate spellings of one entity - the configuration branches of an
    /// `#if` family, for example log4cxx's `logchar`, which aliases `char` in
    /// the UTF-8 branch and `UniChar` in the unichar branch. Their alias
    /// targets differ; canonicalizing each branch on its own and then demanding
    /// agreement reports an ambiguity that denies every declaration in the
    /// family its usages (#1845). The family names `target` when it declares
    /// it, or when one branch's alias chain reaches it.
    ///
    /// Declarations in different files or namespaces are distinct entities and
    /// are deliberately excluded: their disagreement is a real ambiguity.
    pub fn same_fqn_type_spelling_for_target<'b>(
        &self,
        analyzer: &CppGraphSource<'_>,
        visible_from: &ProjectFile,
        candidates: &[&'b CodeUnit],
        target: &CodeUnit,
    ) -> Option<&'b CodeUnit> {
        let [first, rest @ ..] = candidates else {
            return None;
        };
        if rest.is_empty()
            || !rest.iter().all(|candidate| {
                candidate.kind() == first.kind()
                    && candidate.fq_name() == first.fq_name()
                    && candidate.source() == first.source()
            })
        {
            return None;
        }
        candidates
            .iter()
            .copied()
            .find(|candidate| same_symbol(candidate, target))
            .or_else(|| {
                candidates.iter().copied().find(|candidate| {
                    self.type_candidate_preserving_target(analyzer, visible_from, candidate, target)
                        .is_some_and(|resolved| same_visible_symbol(&resolved, target))
                })
            })
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

    /// The byte range of the one `#if` family with a terminal `#else` that holds
    /// every physical declaration of every candidate, or `None` when they do not
    /// share one such family.
    ///
    /// Guard terms alone cannot distinguish one `#if` family from separate blocks
    /// whose macros changed between declarations. Require every physical range to
    /// belong to one syntax-tree family with a terminal `#else` before the terms
    /// can prove branch coverage.
    fn declarations_share_exhaustive_conditional_family(
        &self,
        analyzer: &CppGraphSource<'_>,
        candidates: &[&CodeUnit],
    ) -> Option<(usize, usize)> {
        let mut family_range = None;
        for candidate in candidates {
            let prepared = self.cpp.prepared_syntax(self.token, candidate.source())?;
            let root = prepared.tree().root_node();
            let mut candidate_family = None;
            for range in analyzer.ranges(candidate) {
                let node = root.descendant_for_byte_range(range.start_byte, range.end_byte)?;
                let family = preprocessor_conditional_family_for_declaration(node)?;
                let key = (family.start_byte(), family.end_byte());
                if candidate_family.is_some_and(|existing| existing != key) {
                    return None;
                }
                candidate_family = Some(key);
            }
            let candidate_family = candidate_family?;
            if family_range.is_some_and(|existing| existing != candidate_family) {
                return None;
            }
            family_range = Some(candidate_family);
        }
        family_range
    }

    pub fn complementary_same_fqn_type_declarations(
        &self,
        analyzer: &CppGraphSource<'_>,
        candidates: &[&CodeUnit],
        target: &CodeUnit,
    ) -> bool {
        if candidates.len() < 2
            || !self.alternate_same_fqn_type_declarations(analyzer, candidates, target)
            || self
                .declarations_share_exhaustive_conditional_family(analyzer, candidates)
                .is_none()
        {
            return false;
        }
        Self::preprocessor_guard_terms_cover_all_paths(
            &self.declaration_family_guard_terms(analyzer, candidates),
        )
    }

    fn declaration_family_guard_terms(
        &self,
        analyzer: &CppGraphSource<'_>,
        candidates: &[&CodeUnit],
    ) -> Vec<HashSet<PreprocessorGuard>> {
        candidates
            .iter()
            .flat_map(|candidate| declaration_guard_requirements(analyzer, self.cpp, candidate))
            .map(|(_, guards)| guards)
            .collect()
    }

    /// A callable name declared on every branch of one completed `#if`/`#else`
    /// family is declared on every configuration path, so a reference below the
    /// whole family sees one of the branches whatever the preprocessor decides.
    /// Answer the family's end byte: only past `#endif` is every branch's
    /// declaration behind the reference.
    ///
    /// This is the callable analogue of `complementary_same_fqn_type_declarations`
    /// and shares both of its primitives. It does not require two distinct
    /// `CodeUnit`s: branches that declare the same signature can collapse into
    /// one unit carrying one physical range per branch.
    ///
    /// The branches are alternate spellings of one declaration, never competing
    /// declarations, so only the first branch stands for the family. Reporting
    /// every branch as visible would turn a name the source declares exactly
    /// once into an ambiguity between build configurations.
    fn exhaustive_guard_family_activation(
        &self,
        analyzer: &CppGraphSource<'_>,
        prepared: &PreparedSyntaxTree,
        candidate: &CodeUnit,
        reference: &CallableReferenceContext<'_>,
    ) -> Option<usize> {
        // Branch coverage says nothing about scope: a block-local declaration
        // stays invisible however many branches declare it.
        if nameable_callable_declaration_nodes(analyzer, prepared, candidate).is_empty() {
            return None;
        }
        let family = self
            .visible_identifier_candidates(candidate.source(), candidate.identifier())
            .filter(|peer| {
                peer.kind() == candidate.kind()
                    && peer.fq_name() == candidate.fq_name()
                    && peer.source() == candidate.source()
            })
            .collect::<Vec<_>>();
        let (_, family_end) =
            self.declarations_share_exhaustive_conditional_family(analyzer, &family)?;
        if !Self::preprocessor_guard_terms_cover_all_paths(
            &self.declaration_family_guard_terms(analyzer, &family),
        ) {
            return None;
        }
        // A reference whose own guards pick one branch already reaches that
        // branch through the ordinary same-guard path; the family must not
        // resurrect the branch the reference contradicts.
        if !declaration_guard_requirements(analyzer, self.cpp, candidate)
            .iter()
            .any(|(_, guards)| guards_compatible_at_reference(guards, reference.guards()))
        {
            return None;
        }
        (first_declaration_byte(analyzer, candidate)?
            == family
                .iter()
                .filter_map(|peer| first_declaration_byte(analyzer, peer))
                .min()?)
        .then_some(family_end)
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
            && left_metadata.is_primary()
            && right_metadata.is_primary()
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

    /// Every indexed type declaration `raw_name` names when it is written in
    /// `declaration`'s namespace: the innermost enclosing namespace that holds
    /// the name wins, otherwise the name is looked up unqualified.
    fn type_candidates_for_declaration<'b>(
        &'b self,
        visible_from: &ProjectFile,
        declaration: &CodeUnit,
        raw_name: &str,
    ) -> Vec<&'b CodeUnit> {
        let Some(normalized) = normalize_reference_name(raw_name) else {
            return Vec::new();
        };
        if let Some(namespace) = cpp_namespace_for(declaration) {
            for prefix in namespace_prefixes(&namespace) {
                let qualified = format!("{prefix}::{normalized}");
                let candidates = self.type_candidates(visible_from, &qualified);
                if !candidates.is_empty() {
                    return candidates;
                }
            }
        }
        self.type_candidates(visible_from, &normalized)
    }

    fn resolve_unique_type_for_declaration(
        &self,
        visible_from: &ProjectFile,
        declaration: &CodeUnit,
        raw_name: &str,
    ) -> Option<CodeUnit> {
        unique_logical_type_candidate(self.type_candidates_for_declaration(
            visible_from,
            declaration,
            raw_name,
        ))
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
        let raw_target = cpp_alias_declaration_target_text(alias.signature()?)?;
        let resolved = self.resolve_type_for_declaration(alias.source(), alias, &raw_target)?;
        match resolved.kind() {
            CodeUnitType::Class => Some(resolved),
            _ if is_type_alias(&resolved) => self.alias_target(&resolved),
            _ => None,
        }
    }

    /// Whether two callable declarations declare one function.
    ///
    /// [`same_logical_symbol`] compares the persisted signature strings, which
    /// embed each parameter type exactly as it was spelled. A header
    /// declaration written inside `namespace zmq { class dist_t { ... } }` says
    /// `send_to_matching(msg_t *)` while its out-of-line body at file scope
    /// says `zmq::msg_t *`, so the string comparison reports two symbols where
    /// C++ ([basic.def], [dcl.fct]) sees one declaration and one definition.
    /// This resolves the written parameter names before comparing them and
    /// reports the same answer the language does for the cases it can prove.
    ///
    /// Everything it cannot prove stays two symbols: a template declaration, a
    /// parameter with no comparable shape, a name that resolves on one side
    /// only, and an alias chain it cannot follow safely (#2010).
    pub fn same_logical_callable(
        &self,
        analyzer: &CppGraphSource<'_>,
        left: &CodeUnit,
        right: &CodeUnit,
    ) -> bool {
        if same_logical_symbol(left, right) {
            return true;
        }
        if left.kind() != right.kind()
            || !left.is_callable()
            || !right.is_callable()
            || left.fq_name() != right.fq_name()
        {
            return false;
        }
        // A template declaration and its out-of-line body can also diverge
        // outside the parameter list - `template <class T>` against
        // `template <typename T>` - and the template head is part of the
        // persisted signature. Deciding template-head equivalence is a
        // separate question, so templates keep string identity.
        if self.callable_is_template_declaration(analyzer, left)
            || self.callable_is_template_declaration(analyzer, right)
        {
            return false;
        }
        let (Some(left_comparable), Some(right_comparable)) = (
            self.callable_comparable(analyzer, left),
            self.callable_comparable(analyzer, right),
        ) else {
            return false;
        };
        // The trailing member `const`, ref-qualifier, `noexcept`, trailing
        // return type and requires-clause are part of C++ callable identity and
        // an out-of-line definition repeats them verbatim, so they must agree
        // as written.
        if left_comparable.suffix != right_comparable.suffix
            || left_comparable.shapes.len() != right_comparable.shapes.len()
        {
            return false;
        }
        left_comparable
            .shapes
            .iter()
            .zip(right_comparable.shapes.iter())
            .all(|(left_slot, right_slot)| match (left_slot, right_slot) {
                (CppComparableSlot::Ellipsis, CppComparableSlot::Ellipsis) => true,
                (CppComparableSlot::Shape(left_shape), CppComparableSlot::Shape(right_shape)) => {
                    self.comparable_shapes_agree(analyzer, left_shape, right_shape)
                }
                // An unstructured parameter records that the reduction failed,
                // not that the two spellings mean the same type, so it agrees
                // with nothing - including another unstructured parameter.
                _ => false,
            })
    }

    /// Compare two parameter shapes node by node with an explicit paired stack.
    ///
    /// Shape variants and cv-qualifiers must agree exactly at every level; only
    /// the named leaves may be spelled differently, and they agree when they
    /// resolve to one type declaration.
    fn comparable_shapes_agree(
        &self,
        analyzer: &CppGraphSource<'_>,
        left: &CppComparableParameter,
        right: &CppComparableParameter,
    ) -> bool {
        let mut stack = vec![(left.root(), right.root())];
        while let Some((left_index, right_index)) = stack.pop() {
            match (left.node(left_index), right.node(right_index)) {
                (
                    CppComparableNode::Named {
                        name: left_name,
                        primitive: left_primitive,
                        konst: left_konst,
                        volatil: left_volatil,
                    },
                    CppComparableNode::Named {
                        name: right_name,
                        primitive: right_primitive,
                        konst: right_konst,
                        volatil: right_volatil,
                    },
                ) => {
                    if left_konst != right_konst
                        || left_volatil != right_volatil
                        || left_primitive != right_primitive
                        || !self.comparable_names_agree(
                            analyzer,
                            left_name,
                            right_name,
                            *left_primitive,
                        )
                    {
                        return false;
                    }
                }
                (
                    CppComparableNode::Pointer {
                        inner: left_inner,
                        konst: left_konst,
                        volatil: left_volatil,
                    },
                    CppComparableNode::Pointer {
                        inner: right_inner,
                        konst: right_konst,
                        volatil: right_volatil,
                    },
                ) => {
                    if left_konst != right_konst || left_volatil != right_volatil {
                        return false;
                    }
                    stack.push((*left_inner, *right_inner));
                }
                (
                    CppComparableNode::Reference { inner: left_inner },
                    CppComparableNode::Reference { inner: right_inner },
                )
                | (
                    CppComparableNode::Array { inner: left_inner },
                    CppComparableNode::Array { inner: right_inner },
                ) => stack.push((*left_inner, *right_inner)),
                (
                    CppComparableNode::Generic {
                        base: left_base,
                        arguments: left_arguments,
                    },
                    CppComparableNode::Generic {
                        base: right_base,
                        arguments: right_arguments,
                    },
                ) => {
                    if left_arguments.len() != right_arguments.len() {
                        return false;
                    }
                    stack.push((*left_base, *right_base));
                    stack.extend(
                        left_arguments.iter().zip(right_arguments.iter()).map(
                            |(left_argument, right_argument)| (*left_argument, *right_argument),
                        ),
                    );
                }
                _ => return false,
            }
        }
        true
    }

    /// Whether two written type names denote one type.
    ///
    /// A primitive denotes the same type in every scope, so its recorded
    /// lexical scope is noise and its spelling decides. A nominal name is
    /// resolved on each side independently: two resolved names agree when they
    /// reach one type declaration, and two unresolved names agree only on
    /// exact agreement of what was written, which is no weaker than the
    /// whole-signature string equality this comparison replaces. Resolution on
    /// one side only is evidence of difference, never of agreement.
    fn comparable_names_agree(
        &self,
        analyzer: &CppGraphSource<'_>,
        left: &StructuredTypeName,
        right: &StructuredTypeName,
        primitive: bool,
    ) -> bool {
        if primitive {
            return left.path() == right.path();
        }
        match (
            self.comparable_name_terminal(analyzer, left),
            self.comparable_name_terminal(analyzer, right),
        ) {
            (Some(left_terminal), Some(right_terminal)) => {
                same_logical_symbol(&left_terminal, &right_terminal)
            }
            (None, None) => {
                left.path() == right.path() && left.is_absolute() == right.is_absolute()
            }
            _ => false,
        }
    }

    /// The class declaration a written type name denotes, or `None` when the
    /// workspace cannot prove one.
    ///
    /// The lookup is a closure-independent lexical-scope prefix walk over the
    /// workspace definition index rather than a visibility lookup: the index
    /// handed to a definition query is rooted at the reference file, and a
    /// body's `.cpp` is almost never in that file's include closure. Any name
    /// this walk resolves is one an enclosing-scope lookup could resolve, so it
    /// cannot invent a type the compiler could not see; `using`-directives are
    /// not modelled, and a name that needs one stays unresolved.
    fn comparable_name_terminal(
        &self,
        analyzer: &CppGraphSource<'_>,
        name: &StructuredTypeName,
    ) -> Option<CodeUnit> {
        let mut current = self.comparable_name_declaration(analyzer, name)?;
        let mut visited = HashSet::default();
        for _ in 0..MAX_COMPARABLE_ALIAS_HOPS {
            // The alias question is asked before the class question, and
            // through `declared_type_alias` rather than `is_type_alias`,
            // because extraction records `using A8 = A7;` as a *Class* unit
            // whose signature is the alias declaration. Reading the kind first
            // would end the chase on the alias itself and report an alias
            // spelling and its underlying class as two types (#2010).
            if !declared_type_alias(analyzer, &current) {
                return current.is_class().then_some(current);
            }
            if !visited.insert(current.clone()) {
                return None;
            }
            let signature = current.signature()?;
            // `cpp_alias_declaration_target_text` reads the declaration's
            // `type` field only, so `typedef Foo *Bar` reports `Foo` and the
            // pointer is silently dropped. Substituting such an alias would
            // fuse `f(Bar)` and `f(Foo)`, which are two functions.
            if cpp_alias_declaration_adds_indirection(signature) {
                return None;
            }
            let raw_target = cpp_alias_declaration_target_text(signature)?;
            current = self.comparable_alias_target(analyzer, &current, &raw_target)?;
        }
        None
    }

    /// The declaration one alias hop lands on: the type `raw_target` names,
    /// looked up from the alias declaration's own enclosing namespace.
    ///
    /// The hop takes the same closure-independent prefix walk the first lookup
    /// took, and deliberately not `resolve_type_for_declaration`: that one
    /// answers out of the `VisibilityIndex`, which is rooted at the reference
    /// file, while the alias declaration this hop starts from is reached
    /// through the workspace definition index and its file need not be in that
    /// root's include closure - where the visibility lookup answers nothing and
    /// the chase would stop on the alias itself (#2010).
    fn comparable_alias_target(
        &self,
        analyzer: &CppGraphSource<'_>,
        alias: &CodeUnit,
        raw_target: &str,
    ) -> Option<CodeUnit> {
        // `raw_target` is the alias declaration's written type text, so it is a
        // plain `::`-joined qualified-id: the same domain the shared symbol-path
        // parser reads, and the same leading `::` that marks an absolute name
        // everywhere else this crate normalizes a reference.
        let absolute = raw_target.trim_start().starts_with("::");
        let normalized = normalize_reference_name(raw_target)?;
        let path = brokk_bifrost_core::analyzer::symbol_path::parse_symbol_path(
            brokk_bifrost_core::analyzer::Language::Cpp,
            &normalized,
        );
        let lexical_scope = cpp_namespace_for(alias).map_or_else(Vec::new, |namespace| {
            brokk_bifrost_core::analyzer::symbol_path::parse_symbol_path(
                brokk_bifrost_core::analyzer::Language::Cpp,
                &namespace,
            )
        });
        let name = StructuredTypeName::new(path, lexical_scope, absolute)?;
        self.comparable_name_declaration(analyzer, &name)
    }

    /// The one type declaration `name` names, by enclosing scope, innermost
    /// first.
    ///
    /// The first prefix depth that names anything decides: an inner scope hides
    /// an outer one, so a match there is the answer even when an outer scope
    /// also declares the name. Several logically distinct declarations at that
    /// depth are an ambiguity this comparison must not guess at.
    fn comparable_name_declaration(
        &self,
        analyzer: &CppGraphSource<'_>,
        name: &StructuredTypeName,
    ) -> Option<CodeUnit> {
        let definitions = analyzer.workspace_definitions();
        let interner = segment_interner();
        let first_depth = if name.is_absolute() {
            0
        } else {
            name.lexical_scope().len()
        };
        for depth in (0..=first_depth).rev() {
            let mut structured = FqName::new();
            for component in name.lexical_scope()[..depth].iter().chain(name.path()) {
                structured.push(interner.intern(component, SegmentKind::Unknown));
            }
            let mut candidates = definitions
                .identifier(&structured)
                .into_iter()
                .filter(|unit| unit.fq().same_segment_texts(&structured))
                .filter(|unit| {
                    unit.kind() == CodeUnitType::Class || declared_type_alias(analyzer, unit)
                });
            let Some(first) = candidates.next() else {
                continue;
            };
            return candidates
                .all(|unit| same_logical_symbol(&unit, &first))
                .then_some(first);
        }
        None
    }

    /// The comparison inputs of one callable declaration, extracted once.
    ///
    /// The comparison itself runs only when two candidates share kind and fully
    /// qualified name but not signature, which is rare; re-reading the same
    /// declaration for every pair in a candidate set is not.
    fn callable_comparable(
        &self,
        analyzer: &CppGraphSource<'_>,
        unit: &CodeUnit,
    ) -> Option<Arc<ExtractedComparable>> {
        if let Some(cached) = self
            .callable_comparables
            .lock()
            .expect("C++ callable comparable cache poisoned")
            .get(unit)
            .cloned()
        {
            return cached;
        }
        let extracted = self
            .extract_callable_comparable(analyzer, unit)
            .map(Arc::new);
        self.callable_comparables
            .lock()
            .expect("C++ callable comparable cache poisoned")
            .insert(unit.clone(), extracted.clone());
        extracted
    }

    fn extract_callable_comparable(
        &self,
        analyzer: &CppGraphSource<'_>,
        unit: &CodeUnit,
    ) -> Option<ExtractedComparable> {
        let prepared = self.cpp.prepared_syntax(self.token, unit.source())?;
        let root = prepared.tree().root_node();
        let declarator = analyzer
            .ranges(unit)
            .into_iter()
            .find_map(|range| cpp_function_declarator_at(root, range.start_byte))?;
        Some(ExtractedComparable {
            // One question about one declarator: indexing the file's tree would
            // cost more than the walk it saves.
            shapes: cpp_comparable_parameter_shapes(
                declarator,
                prepared.source(),
                &ParentIndex::unindexed(),
            ),
            suffix: cpp_callable_identity_suffix(declarator, prepared.source())?,
        })
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
            self.parser_alias_source_parses
                .fetch_add(1, Ordering::Relaxed);
            #[cfg(any(test, feature = "test-support"))]
            {
                *self
                    .alias_source_parse_counts
                    .lock()
                    .expect("alias source parse count lock")
                    .entry(file.clone())
                    .or_default() += 1;
            }
            aliases_from_prepared_source(cpp, self.token, file).into_boxed_slice()
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
    /// Parser-only aliases are tested lazily when their spelling is actually
    /// encountered in a scanned type node. Enumerating them here would parse
    /// every source in the include closure even when the target's direct name
    /// is the only spelling present in the file.
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
        let Some(prepared) = self.cpp.prepared_syntax(self.token, candidate.source()) else {
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

    /// Whether a callable declaration is a class-template deduction guide.
    ///
    /// Tree-sitter represents `Box(T) -> Box<T>;` as a declaration with no
    /// type field whose function declarator owns a trailing return type. This
    /// structured shape distinguishes a guide from both a constructor (no
    /// trailing return) and an ordinary trailing-return function (an `auto`
    /// type field).
    pub fn callable_is_deduction_guide_declaration(
        &self,
        analyzer: &CppGraphSource<'_>,
        candidate: &CodeUnit,
    ) -> bool {
        if !candidate.is_function() {
            return false;
        }
        let Some(prepared) = self.cpp.prepared_syntax(self.token, candidate.source()) else {
            return false;
        };
        nameable_callable_declaration_nodes(analyzer, prepared.as_ref(), candidate)
            .into_iter()
            .any(|declaration| {
                if declaration.kind() != "declaration"
                    || declaration.child_by_field_name("type").is_some()
                {
                    return false;
                }
                let Some(declarator) = declaration.child_by_field_name("declarator") else {
                    return false;
                };
                if declarator.kind() != "function_declarator" {
                    return false;
                }
                let mut cursor = declarator.walk();
                let has_trailing_return = declarator
                    .named_children(&mut cursor)
                    .any(|child| child.kind() == "trailing_return_type");
                has_trailing_return
                    && declarator_name_node(declarator).is_some_and(|name| {
                        node_text(name, prepared.source()) == candidate.identifier()
                    })
            })
    }

    /// Whether a callable occurrence is directly wrapped by a C++ template
    /// declaration. This deliberately inspects declaration syntax instead of
    /// inferring template status from the rendered signature.
    pub fn callable_is_template_declaration(
        &self,
        analyzer: &CppGraphSource<'_>,
        candidate: &CodeUnit,
    ) -> bool {
        if !candidate.is_function() {
            return false;
        }
        let Some(prepared) = self.cpp.prepared_syntax(self.token, candidate.source()) else {
            return false;
        };
        let root = prepared.tree().root_node();
        analyzer.ranges(candidate).iter().any(|range| {
            let Some(node) = node_for_exact_range(root, range)
                .or_else(|| root.descendant_for_byte_range(range.start_byte, range.end_byte))
            else {
                return false;
            };
            node.parent().is_some_and(|parent| {
                parent.kind() == "template_declaration"
                    && parent
                        .named_child(parent.named_child_count().saturating_sub(1))
                        .is_some_and(|declaration| same_node(declaration, node))
            })
        })
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

    fn reachable_files(
        &self,
        root: &ProjectFile,
        cancellation: Option<&CancellationToken>,
    ) -> HashSet<ProjectFile> {
        let mut pending = vec![root.clone()];
        let mut visited = HashSet::default();
        while let Some(file) = pending.pop() {
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                break;
            }
            if visited.insert(file.clone()) {
                pending.extend(self.targets(&file).iter().cloned());
            }
        }
        visited
    }
}

fn build_bounded_visible_declarations(
    cpp: &dyn CppSource,
    token: QueryToken<'_>,
    analyzer: &CppGraphSource<'_>,
    roots: &HashSet<ProjectFile>,
    visible_sources: &HashMap<ProjectFile, HashSet<ProjectFile>>,
    cancellation: Option<&CancellationToken>,
    stats: &mut BoundedVisibilityStats,
) -> HashMap<ProjectFile, HashSet<CodeUnit>> {
    roots
        .iter()
        .map(|root| {
            let reading_is_c = analyzer.reference_uses_c_semantics(root);
            let declarations_started = Instant::now();
            let root_declarations =
                bounded_visibility_declarations_in_reading(analyzer, root, reading_is_c);
            stats.declaration_elapsed += declarations_started.elapsed();
            stats.declaration_reads += 1;
            stats.declaration_units += root_declarations.len();
            let mut visible = root_declarations.into_iter().collect::<HashSet<_>>();
            let mut pending_names = HashSet::default();
            if let Some(prepared) = cpp.prepared_syntax(token, root) {
                let mut pending_nodes = vec![prepared.tree().root_node()];
                while let Some(node) = pending_nodes.pop() {
                    if matches!(
                        node.kind(),
                        "identifier"
                            | "type_identifier"
                            | "field_identifier"
                            | "namespace_identifier"
                    ) {
                        pending_names.insert(node_text(node, prepared.source()).to_string());
                    }
                    if node.kind() == "preproc_arg" {
                        for reference in
                            object_macro_replacement_type_references(node, prepared.source())
                        {
                            pending_names.extend(reference.components);
                        }
                    }
                    for index in 0..node.named_child_count() {
                        if let Some(child) = node.named_child(index) {
                            pending_nodes.push(child);
                        }
                    }
                }
            }
            stats.root_names += pending_names.len();
            let mut completed_names = HashSet::default();
            while !pending_names.is_empty() {
                stats.rounds += 1;
                let round_names = std::mem::take(&mut pending_names);
                let mut requested_names_by_source: HashMap<ProjectFile, HashSet<String>> =
                    HashMap::default();
                for identifier in round_names {
                    if !completed_names.insert(identifier.clone())
                        || cancellation.is_some_and(CancellationToken::is_cancelled)
                    {
                        continue;
                    }
                    let lookup_started = Instant::now();
                    let candidates = cpp.visibility_identifier_candidates(&identifier);
                    stats.lookup_elapsed += lookup_started.elapsed();
                    stats.identifier_lookups += 1;
                    stats.candidate_units += candidates.len();
                    for source in candidates
                        .into_iter()
                        .map(|unit| unit.source().clone())
                        .collect::<HashSet<_>>()
                    {
                        if source != *root
                            && visible_sources
                                .get(root)
                                .is_some_and(|files| files.contains(&source))
                        {
                            requested_names_by_source
                                .entry(source)
                                .or_default()
                                .insert(identifier.clone());
                        }
                    }
                }
                stats.candidate_sources += requested_names_by_source.len();
                for (source, requested_names) in requested_names_by_source {
                    let declarations_started = Instant::now();
                    let declarations =
                        bounded_visibility_declarations_in_reading(analyzer, &source, reading_is_c);
                    stats.declaration_elapsed += declarations_started.elapsed();
                    stats.declaration_reads += 1;
                    stats.declaration_units += declarations.len();
                    for unit in declarations {
                        let template_metadata = unit
                            .is_class()
                            .then(|| cpp.template_metadata(&unit))
                            .flatten();
                        if !requested_names.contains(unit.identifier())
                            && !template_metadata.as_ref().is_some_and(|metadata| {
                                requested_names.contains(&metadata.primary_name)
                            })
                        {
                            continue;
                        }
                        stats.selected_units += 1;
                        if let Some(prepared) = cpp.prepared_syntax(token, &source) {
                            let ast_started = Instant::now();
                            for range in analyzer.ranges(&unit) {
                                let Some(declaration) =
                                    node_for_exact_range(prepared.tree().root_node(), &range)
                                else {
                                    continue;
                                };
                                let mut pending_nodes = vec![declaration];
                                while let Some(node) = pending_nodes.pop() {
                                    stats.dependency_ast_nodes += 1;
                                    if matches!(
                                        node.kind(),
                                        "type_identifier" | "namespace_identifier"
                                    ) {
                                        let name = node_text(node, prepared.source());
                                        if !completed_names.contains(name)
                                            && pending_names.insert(name.to_string())
                                        {
                                            stats.dependency_names += 1;
                                        }
                                    }
                                    for index in 0..node.named_child_count() {
                                        if let Some(child) = node.named_child(index) {
                                            pending_nodes.push(child);
                                        }
                                    }
                                }
                            }
                            stats.dependency_ast_elapsed += ast_started.elapsed();
                        }
                        if let Some(metadata) = template_metadata
                            && !completed_names.contains(&metadata.primary_name)
                        {
                            pending_names.insert(metadata.primary_name);
                        }
                        visible.insert(unit);
                    }
                }
            }
            (root.clone(), visible)
        })
        .collect()
}

#[derive(Default)]
struct BoundedVisibilityStats {
    rounds: usize,
    root_names: usize,
    identifier_lookups: usize,
    candidate_units: usize,
    candidate_sources: usize,
    declaration_reads: usize,
    declaration_units: usize,
    selected_units: usize,
    dependency_ast_nodes: usize,
    dependency_names: usize,
    lookup_elapsed: Duration,
    declaration_elapsed: Duration,
    dependency_ast_elapsed: Duration,
}

fn bounded_visibility_declarations_in_reading(
    analyzer: &CppGraphSource<'_>,
    file: &ProjectFile,
    c_semantics: bool,
) -> BTreeSet<CodeUnit> {
    #[cfg(any(test, feature = "test-support"))]
    BOUNDED_VISIBILITY_DECLARATION_READ_COUNT.with(|count| count.set(count.get() + 1));
    analyzer.declarations_in_reading(file, c_semantics)
}

#[cfg(any(test, feature = "test-support"))]
pub fn reset_bounded_visibility_declaration_read_count_for_test() {
    BOUNDED_VISIBILITY_DECLARATION_READ_COUNT.with(|count| count.set(0));
}

#[cfg(any(test, feature = "test-support"))]
pub fn bounded_visibility_declaration_read_count_for_test() -> usize {
    BOUNDED_VISIBILITY_DECLARATION_READ_COUNT.with(Cell::get)
}

pub struct VisibilityData {
    pub visible_by_file: HashMap<ProjectFile, HashSet<CodeUnit>>,
    pub visible_source_files_by_root: HashMap<ProjectFile, HashSet<ProjectFile>>,
}

/// Build the per-root include closure and the declarations each root can see
/// through it.
///
/// `declarations_for` takes the reading to answer in (issue #1970): a root
/// compiled as C sees the C reading of every file in its closure, a root
/// compiled as C++ sees the C++ reading, and `reading_is_c_for` decides which
/// per root. The two readings agree for all but a handful of headers, so the
/// C map is built only when some root actually asks for it, and only over the
/// files that root reaches.
pub fn build_visibility_data<F, R, D>(
    roots: &HashSet<ProjectFile>,
    cancellation: Option<&CancellationToken>,
    mut targets_for: F,
    mut reading_is_c_for: R,
    mut declarations_for: D,
) -> VisibilityData
where
    F: FnMut(&ProjectFile) -> Vec<ProjectFile>,
    R: FnMut(&ProjectFile) -> bool,
    D: FnMut(&ProjectFile, bool) -> BTreeSet<CodeUnit>,
{
    let mut include_graph = IncludeGraph::default();
    for file in roots {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            break;
        }
        include_graph.extend_with(file, cancellation, &mut targets_for);
    }
    let cpp_declarations_by_file: HashMap<ProjectFile, BTreeSet<CodeUnit>> = include_graph
        .files()
        .take_while(|_| !cancellation.is_some_and(CancellationToken::is_cancelled))
        .map(|file| (file.clone(), declarations_for(file, false)))
        .collect();
    let mut c_declarations_by_file: HashMap<ProjectFile, BTreeSet<CodeUnit>> = HashMap::default();
    let mut visible_by_file = HashMap::default();
    let mut visible_source_files_by_root = HashMap::default();
    for file in roots {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            break;
        }
        let mut visited = HashSet::default();
        let mut visible = HashSet::default();
        let declarations_by_file = if reading_is_c_for(file) {
            for reached in cpp_declarations_by_file.keys() {
                if !c_declarations_by_file.contains_key(reached) {
                    let declarations = declarations_for(reached, true);
                    c_declarations_by_file.insert(reached.clone(), declarations);
                }
            }
            &c_declarations_by_file
        } else {
            &cpp_declarations_by_file
        };
        collect_visible_declarations(
            &include_graph,
            declarations_by_file,
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

/// Admit the class that an out-of-line definition proves is in scope.
///
/// `Owner::member(...) { ... }` in a file is structured proof that `Owner`
/// names a class-like entity in that file's scope: a member declaration can
/// live in a file other than its class's only when it is written out of line.
/// A file a build concatenates rather than compiles carries no `#include` edge
/// to the header declaring `Owner` -- google/wuffs
/// `internal/cgen/auxiliary/image.cc` defines
/// `DecodeImageResult::DecodeImageResult` and never includes `image.hh` -- so
/// every unqualified member and constructor reference in it had no candidate at
/// all (#1832).
///
/// The evidence is the indexed declaration's own owner name, taken from its
/// `FqName`, so this stays a structured answer rather than a text fallback.
/// Only an owner the file cannot already see is admitted: that is what keeps a
/// header declaring its own class from additionally seeing every same-named
/// class in the workspace, and it makes the pass free for the ordinary file
/// whose owners are all visible.
#[derive(Default)]
struct OutOfLineOwnerBindingStats {
    unseen_owners: usize,
    definition_lookups: usize,
    admitted: usize,
}

fn extend_with_out_of_line_owner_bindings(
    cpp: &dyn CppSource,
    visible_by_file: &mut HashMap<ProjectFile, HashSet<CodeUnit>>,
) -> OutOfLineOwnerBindingStats {
    let mut stats = OutOfLineOwnerBindingStats::default();
    for (file, visible) in visible_by_file.iter_mut() {
        // The include-closure walk seeds every root with its own declarations,
        // so the file's members are already here; re-reading them from the
        // analyzer would pay for the same declaration set twice.
        let mut unseen_owners: HashSet<String> = visible
            .iter()
            .filter(|unit| unit.source() == file && (unit.is_function() || unit.is_field()))
            .filter_map(brokk_bifrost_core::analyzer::default_parent_fq_name)
            .collect();
        if unseen_owners.is_empty() {
            continue;
        }
        for unit in visible.iter().filter(|unit| unit.is_class()) {
            unseen_owners.remove(&unit.fq_name());
        }
        stats.unseen_owners += unseen_owners.len();
        stats.definition_lookups += unseen_owners.len();
        let admitted = unseen_owners
            .iter()
            .flat_map(|owner| cpp.definitions(owner))
            .filter(CodeUnit::is_class)
            .collect::<Vec<_>>();
        stats.admitted += admitted.len();
        visible.extend(admitted);
    }
    stats
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

/// Resolve the declaring owner of a callable after applying a member
/// `using <Base>::<member>;` declaration to one exact call arity.
///
/// Ordinary member lookup is intentionally name-based: the first class that
/// declares a name hides the same name on deeper bases. A member
/// using-declaration is the one exception. When none of the declarations on
/// that first owner accepts the call arity, it can reintroduce an applicable
/// overload from the named base. If a declaration on the first owner does
/// accept the arity, argument types would be needed to choose between it and
/// a same-arity introduced overload, so this resolver conservatively keeps the
/// ordinary owner (#1835/#1843).
///
/// The caller supplies ordinary name-based owner resolution so a file scan can
/// reuse its existing owner cache before applying this callable-only exception.
pub fn resolve_declaring_callable_owner(
    analyzer: &CppGraphSource<'_>,
    visibility: &VisibilityIndex<'_>,
    file: &ProjectFile,
    ordinary: EnclosingMemberOwnerResolution,
    member_name: &str,
    call_arity: usize,
) -> EnclosingMemberOwnerResolution {
    let EnclosingMemberOwnerResolution::Owner(ordinary_owner) = &ordinary else {
        return ordinary;
    };
    if visibility
        .visible_members_for_owner_name(file, ordinary_owner, member_name)
        .into_iter()
        .any(|unit| unit.is_function() && cpp_callable_arity(analyzer, unit).accepts(call_arity))
    {
        return ordinary;
    }

    let mut pending = match member_using_declaration_bases(
        analyzer,
        visibility,
        file,
        ordinary_owner,
        member_name,
    ) {
        Ok(bases) => bases,
        Err(()) => return EnclosingMemberOwnerResolution::Ambiguous,
    };
    let mut visited = HashSet::default();
    let mut introduced_owners = Vec::new();
    while let Some(owner) = pending.pop() {
        if !visited.insert(owner.clone()) {
            continue;
        }
        let accepts_arity = visibility
            .visible_members_for_owner_name(file, &owner, member_name)
            .into_iter()
            .any(|unit| {
                unit.is_function() && cpp_callable_arity(analyzer, unit).accepts(call_arity)
            });
        if accepts_arity {
            if !introduced_owners
                .iter()
                .any(|existing| same_visible_symbol(existing, &owner))
            {
                introduced_owners.push(owner);
            }
            continue;
        }
        match member_using_declaration_bases(analyzer, visibility, file, &owner, member_name) {
            Ok(bases) => pending.extend(bases),
            Err(()) => return EnclosingMemberOwnerResolution::Ambiguous,
        }
    }
    match introduced_owners.as_slice() {
        [] => ordinary,
        [owner] => EnclosingMemberOwnerResolution::Owner(owner.clone()),
        _ => EnclosingMemberOwnerResolution::Ambiguous,
    }
}

fn member_using_declaration_bases(
    analyzer: &CppGraphSource<'_>,
    visibility: &VisibilityIndex<'_>,
    file: &ProjectFile,
    owner: &CodeUnit,
    member_name: &str,
) -> Result<Vec<CodeUnit>, ()> {
    let Some(source) = analyzer.get_source(owner, false) else {
        return Ok(Vec::new());
    };
    let scopes = cpp_member_using_declaration_scopes(&source, member_name);
    if scopes.is_empty() {
        return Ok(Vec::new());
    }
    let Some(hierarchy) = analyzer.type_hierarchy_provider() else {
        return Ok(Vec::new());
    };
    let mut bases = Vec::new();
    for raw_ancestor in hierarchy.get_ancestors(owner) {
        let Some(ancestor) =
            visibility.canonical_visible_full_type_unit(analyzer, file, &raw_ancestor)
        else {
            return Err(());
        };
        let qualified = cpp_name_for(&ancestor);
        if scopes
            .iter()
            .any(|scope| cpp_qualified_name_has_scope_suffix(&qualified, scope))
            && !bases
                .iter()
                .any(|existing| same_visible_symbol(existing, &ancestor))
        {
            bases.push(ancestor);
        }
    }
    Ok(bases)
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
            .then_with(|| left.kind().cmp(&right.kind()))
            .then_with(|| {
                left.package_segment_count()
                    .cmp(&right.package_segment_count())
            })
            .then_with(|| left.is_synthetic().cmp(&right.is_synthetic()))
            .then_with(|| stable_fq_name_cmp(left.fq(), right.fq()))
    });
}

fn stable_fq_name_cmp(left: &FqName, right: &FqName) -> CmpOrdering {
    let interner = segment_interner();
    for (&left_id, &right_id) in left.segments().iter().zip(right.segments()) {
        let (left_text, left_kind) = interner.resolve(left_id);
        let (right_text, right_kind) = interner.resolve(right_id);
        let order = left_text
            .cmp(right_text)
            .then_with(|| segment_kind_order(left_kind).cmp(&segment_kind_order(right_kind)));
        if order != CmpOrdering::Equal {
            return order;
        }
    }
    left.len().cmp(&right.len())
}

const fn segment_kind_order(kind: SegmentKind) -> u8 {
    match kind {
        SegmentKind::Path => 0,
        SegmentKind::Package => 1,
        SegmentKind::Type => 2,
        SegmentKind::Companion => 3,
        SegmentKind::Nested => 4,
        SegmentKind::Member => 5,
        SegmentKind::Unknown => 6,
    }
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
            | TargetKind::MemberField
            | TargetKind::Macro => {
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
            // `a().b()` and `p->b()` invoke a member on a receiver *value*. The
            // callee's source text is an expression, not a name, and every name
            // lookup below normalizes a reference by truncating at the first
            // `(`: `first().second` would read as `first`, so the chained call
            // would take the type of `first()` instead of the type of
            // `first().second()` (#2178). Only the member path can answer for
            // this shape, so route to it from the callee's node kind.
            if function.kind() == "field_expression" {
                let arity = visibility.call_arity_evidence(file, node, source).exact()?;
                return resolve_field_method_call_return_binding(
                    analyzer,
                    visibility,
                    file,
                    source,
                    function,
                    arity,
                    receiver_resolver,
                );
            }
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
            // Only the return-typed branches need the argument count. An
            // unknown arity leaves them out, exactly as in the template arm
            // above, and still constructs the direct type: `File(getPath())`
            // names `File` whether or not `getPath()`'s expansion is provable.
            let arity = visibility.call_arity_evidence(file, node, source).exact();
            if let Some(arity) = arity {
                let direct_type_binding_for_call = direct_type_binding.clone();
                if let Some(binding) = resolve_static_method_call_return_binding(
                    analyzer, visibility, file, source, function, arity,
                )
                .or_else(|| {
                    // An applicable free function supplies the receiver value
                    // before an unrelated visible type with the same terminal
                    // name. The direct type still excludes its own constructor
                    // declaration below and remains the construction fallback.
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
                }) {
                    return Some(binding);
                }
            }
            direct_type_binding
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
    debug_assert_eq!(
        function.kind(),
        "field_expression",
        "the member-call return binding answers only for a field-expression callee"
    );
    let receiver_resolver = receiver_resolver?;
    let field = function.child_by_field_name("field")?;
    let member_name = node_text(function_terminal_node(field), source);
    let receiver = function
        .child_by_field_name("argument")
        .or_else(|| function.named_child(0))?;
    let owners = receiver_resolver(receiver, source);
    let mut candidates = Vec::new();
    for owner in owners {
        let declaring_owner =
            match resolve_declaring_member_owner(analyzer, visibility, file, &owner, member_name) {
                EnclosingMemberOwnerResolution::Owner(owner) => owner,
                EnclosingMemberOwnerResolution::Missing => continue,
                EnclosingMemberOwnerResolution::Ambiguous => return None,
            };
        candidates.extend(
            visibility
                .visible_members_for_owner_name(file, &declaring_owner, member_name)
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

fn aliases_from_prepared_source(
    cpp: &dyn CppSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
) -> Vec<CppAlias> {
    let Some(prepared) = cpp.prepared_syntax(token, file) else {
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

pub fn cpp_callable_parameter_types(
    analyzer: &CppGraphSource<'_>,
    unit: &CodeUnit,
) -> Option<Vec<String>> {
    analyzer
        .signature_metadata(unit)
        .into_iter()
        .find_map(|metadata| metadata.callable_parameter_types().map(<[String]>::to_vec))
        .or_else(|| unit.signature().and_then(cpp_signature_param_types))
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
    token: QueryToken<'_>,
    file: &ProjectFile,
    prepared: &PreparedSyntaxTree,
    donor_source: &ProjectFile,
) -> Option<usize> {
    let include_targets = cpp.include_target_index();
    let mut direct_includes = Vec::new();
    let mut nodes = vec![prepared.tree().root_node()];
    // An include activates for the whole file, so only an unconditional
    // directive counts here.
    let reference = CallableReferenceContext {
        file,
        position: None,
    };
    while let Some(node) = nodes.pop() {
        if node.kind() == "preproc_include" {
            if callable_preprocessor_context_is_visible_for_reference(
                node,
                prepared.source(),
                &reference,
            ) {
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
                token,
                include_targets,
                direct,
                donor_source,
                file,
                &mut known_missing,
            )
        })
        .map(|(activation, _)| activation)
}

fn find_conditional_include_projection_index(
    cpp: &dyn CppSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    prepared: &PreparedSyntaxTree,
    on_state: &dyn Fn(),
) -> ConditionalIncludeProjectionIndex {
    let include_targets = cpp.include_target_index();
    let mut projections_by_source: HashMap<ProjectFile, Vec<ConditionalIncludeProjection>> =
        HashMap::default();
    let mut pending = Vec::new();
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
                pending.push((target, node.end_byte(), required_guards.clone()));
            }
            continue;
        }
        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(index) {
                nodes.push(child);
            }
        }
    }

    // One reached file can have several distinct compatible guard paths. Each
    // (file, activation byte) key keeps only the inclusion-minimal guard sets:
    // the consumers ask existence questions whose answers are monotone in the
    // guard set -- a path whose requirements hold, stay stable, and stay
    // compatible under one environment does so under every subset as well --
    // so a state subsumed by an existing subset cannot witness anything its
    // subset does not, and inserting a smaller set evicts the supersets it
    // subsumes. Exact-set dedup still terminated cycles, but dense `#ifdef`
    // lattices (QMK's per-keyboard feature guards) enumerated the powerset of
    // path-union guard sets through it: the state space, the per-key linear
    // scans, and resident memory all grew without bound (#2365).
    let mut expanded: HashMap<(ProjectFile, usize), Vec<HashSet<PreprocessorGuard>>> =
        HashMap::default();
    while let Some((current_file, activation_byte, required_guards)) = pending.pop() {
        let guard_sets = expanded
            .entry((current_file.clone(), activation_byte))
            .or_default();
        if guard_sets
            .iter()
            .any(|existing| existing.is_subset(&required_guards))
        {
            continue;
        }
        let (evicted, kept): (Vec<_>, Vec<_>) = guard_sets
            .drain(..)
            .partition(|existing| required_guards.is_subset(existing));
        *guard_sets = kept;
        guard_sets.push(required_guards.clone());
        if !evicted.is_empty()
            && let Some(projections) = projections_by_source.get_mut(&current_file)
        {
            projections.retain(|projection| {
                projection.activation_byte != activation_byte
                    || !evicted.contains(&projection.required_guards)
            });
        }
        on_state();

        // A fresh minimal set has no equal in the store: equality would have
        // been caught by the subset check above.
        projections_by_source
            .entry(current_file.clone())
            .or_default()
            .push(ConditionalIncludeProjection {
                activation_byte,
                required_guards: required_guards.clone(),
            });

        let Some(current_prepared) = cpp.prepared_syntax(token, &current_file) else {
            continue;
        };
        let mut nodes = vec![current_prepared.tree().root_node()];
        while let Some(node) = nodes.pop() {
            if node.kind() == "preproc_include" {
                let Some(include_guards) =
                    preprocessor_guard_environment(node, current_prepared.source())
                else {
                    continue;
                };
                let Some(path_guards) =
                    merge_preprocessor_guards(&required_guards, &include_guards)
                else {
                    continue;
                };
                let raw = normalize_cpp_whitespace(node_text(node, current_prepared.source()));
                for include in cpp_include_paths(std::slice::from_ref(&raw)) {
                    let Some(target) = unique_include_target(resolve_include_targets_with_index(
                        &current_file,
                        &include,
                        include_targets,
                    )) else {
                        continue;
                    };
                    pending.push((target, activation_byte, path_guards.clone()));
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

    projections_by_source
        .into_iter()
        .map(|(source, mut projections)| {
            projections.sort_by_key(|projection| projection.activation_byte);
            (source, Arc::from(projections))
        })
        .collect()
}

/// Decide one conditional include target without materializing every source
/// reached by every guard combination. Paths whose requirements do not hold
/// at the reference cannot become feasible after adding nested include guards,
/// so discard them before expanding the next header.
#[allow(clippy::too_many_arguments)]
fn find_conditional_include_projection_for_source(
    cpp: &dyn CppSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    prepared: &PreparedSyntaxTree,
    donor_source: &ProjectFile,
    reference_guards: Option<&HashSet<PreprocessorGuard>>,
    reference_byte: usize,
    on_state: &dyn Fn(),
) -> bool {
    let Some(reference_guards) = reference_guards else {
        return false;
    };
    let include_targets = cpp.include_target_index();
    let mut pending = Vec::new();
    let mut nodes = vec![prepared.tree().root_node()];
    while let Some(node) = nodes.pop() {
        if node.kind() == "preproc_include" {
            let Some(required_guards) = preprocessor_guard_environment(node, prepared.source())
            else {
                continue;
            };
            if node.end_byte() > reference_byte
                || !guard_requirements_hold_at_reference(&required_guards, Some(reference_guards))
            {
                continue;
            }
            let raw = normalize_cpp_whitespace(node_text(node, prepared.source()));
            for include in cpp_include_paths(std::slice::from_ref(&raw)) {
                let Some(target) = unique_include_target(resolve_include_targets_with_index(
                    file,
                    &include,
                    include_targets,
                )) else {
                    continue;
                };
                if &target == donor_source {
                    return true;
                }
                pending.push((target, required_guards.clone()));
            }
            continue;
        }
        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(index) {
                nodes.push(child);
            }
        }
    }

    let mut expanded: HashMap<ProjectFile, Vec<HashSet<PreprocessorGuard>>> = HashMap::default();
    while let Some((current_file, required_guards)) = pending.pop() {
        let guard_sets = expanded.entry(current_file.clone()).or_default();
        if guard_sets.contains(&required_guards) {
            continue;
        }
        guard_sets.push(required_guards.clone());
        on_state();

        let Some(current_prepared) = cpp.prepared_syntax(token, &current_file) else {
            continue;
        };
        let mut nodes = vec![current_prepared.tree().root_node()];
        while let Some(node) = nodes.pop() {
            if node.kind() == "preproc_include" {
                let Some(include_guards) =
                    preprocessor_guard_environment(node, current_prepared.source())
                else {
                    continue;
                };
                let Some(path_guards) =
                    merge_preprocessor_guards(&required_guards, &include_guards)
                else {
                    continue;
                };
                if !guard_requirements_hold_at_reference(&path_guards, Some(reference_guards)) {
                    continue;
                }
                let raw = normalize_cpp_whitespace(node_text(node, current_prepared.source()));
                for include in cpp_include_paths(std::slice::from_ref(&raw)) {
                    let Some(target) = unique_include_target(resolve_include_targets_with_index(
                        &current_file,
                        &include,
                        include_targets,
                    )) else {
                        continue;
                    };
                    if &target == donor_source {
                        return true;
                    }
                    pending.push((target, path_guards.clone()));
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
    false
}

/// Whether `translation_unit`'s unconditional `#include` closure reaches
/// `header`, directly or through any chain of headers.
///
/// The include-closure question asked on its own, for
/// [`crate::identity::cpp_header_body_files_are_related`]. The walk resolves
/// each include the way visibility does -- to a unique target or to nothing --
/// so a duplicated basename relates nothing, and it is memoized per file pair
/// on the analyzer.
///
/// The reference position is `translation_unit` itself: the question is
/// whether that unit compiles the header, so that unit's own dialect and
/// preprocessor context govern the walk.
pub fn cpp_include_closure_reaches(
    cpp: &dyn CppSource,
    token: QueryToken<'_>,
    translation_unit: &ProjectFile,
    header: &ProjectFile,
) -> bool {
    unconditional_include_reaches(
        cpp,
        token,
        cpp.include_target_index(),
        translation_unit,
        header,
        translation_unit,
        &mut HashSet::default(),
    )
}

fn unconditional_include_reaches(
    cpp: &dyn CppSource,
    token: QueryToken<'_>,
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
    // Only an unconditional directive extends the include reach, so the walk
    // asks the question without a reference position.
    let reference = CallableReferenceContext {
        file: reference_file,
        position: None,
    };
    while let Some(file) = files.pop() {
        if file == *donor_source {
            cpp.cache_unconditional_include_reachability(first, donor_source, reference_is_c, true);
            return true;
        }
        if known_missing.contains(&file) || !visited.insert(file.clone()) {
            continue;
        }
        let Some(prepared) = cpp.prepared_syntax(token, &file) else {
            continue;
        };
        let mut nodes = vec![prepared.tree().root_node()];
        while let Some(node) = nodes.pop() {
            if node.kind() == "preproc_include" {
                if callable_preprocessor_context_is_visible_for_reference(
                    node,
                    prepared.source(),
                    &reference,
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
    let Some(prepared) = cpp.prepared_syntax(analyzer.token, candidate.source()) else {
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

fn first_declaration_byte(analyzer: &CppGraphSource<'_>, candidate: &CodeUnit) -> Option<usize> {
    analyzer
        .ranges(candidate)
        .into_iter()
        .map(|range| range.start_byte)
        .min()
}

/// The macro names every configuration in `contexts` defines -- the fact set
/// one file's compile-database coverage proves (#2011). `None` when the
/// database has no entry for the file, which is different from an empty
/// intersection: no entry means no coverage, while an empty intersection is
/// covered-and-proves-nothing.
fn context_fact_names(contexts: &[CppCompileContext]) -> Option<HashSet<String>> {
    let (first, rest) = contexts.split_first()?;
    Some(
        first
            .defined_macros
            .iter()
            .filter(|name| {
                rest.iter()
                    .all(|context| context.defined_macros.contains(*name))
            })
            .cloned()
            .collect(),
    )
}

fn guard_requirements_hold_at_reference(
    required: &HashSet<PreprocessorGuard>,
    reference: Option<&HashSet<PreprocessorGuard>>,
) -> bool {
    reference.is_some_and(|active| {
        required
            .iter()
            .all(|guard| preprocessor_guard_holds_at_reference(guard, active))
    })
}

fn preprocessor_guard_holds_at_reference(
    required: &PreprocessorGuard,
    active: &HashSet<PreprocessorGuard>,
) -> bool {
    if active.contains(required) {
        return true;
    }
    let active_expression = BooleanGuardExpression::all(
        active
            .iter()
            .filter_map(PreprocessorGuard::as_boolean_expression),
    );
    required
        .as_boolean_expression()
        .is_some_and(|required| active_expression.implies(&required))
}

/// Cross-file guard rule: two guard sets are compatible when neither one
/// contradicts the other. Use this instead of the subset test whenever the
/// guards come from a foreign file, which resolves its own conditionals
/// independently of the reference.
fn guards_compatible_at_reference(
    declaration: &HashSet<PreprocessorGuard>,
    reference: Option<&HashSet<PreprocessorGuard>>,
) -> bool {
    reference.is_some_and(|active| merge_preprocessor_guards(declaration, active).is_some())
}

/// The byte range of the `#if`/`#elif`/`#else` chain that encloses the smallest
/// node covering `[start_byte, end_byte)`, or `None` when nothing there is
/// conditional.
///
/// Two declarations of one name that report the same chain stand in different
/// branches of it, so at most one of them is compiled in any configuration.
/// They are alternate spellings of a single declaration, not competing
/// declarations, and navigation must not present them as an ambiguity.
pub fn preprocessor_conditional_family_range(
    root: Node<'_>,
    start_byte: usize,
    end_byte: usize,
) -> Option<(usize, usize)> {
    let node = root.descendant_for_byte_range(start_byte, end_byte)?;
    let mut ancestor = Some(node);
    while let Some(current) = ancestor {
        if is_preprocessor_conditional(current)
            && preprocessor_conditional_contains_descendant(current, node)
        {
            let family = preprocessor_conditional_family_root(current);
            return Some((family.start_byte(), family.end_byte()));
        }
        ancestor = current.parent();
    }
    None
}

fn preprocessor_conditional_family_for_declaration(node: Node<'_>) -> Option<Node<'_>> {
    let mut ancestor = node.parent();
    while let Some(current) = ancestor {
        if is_preprocessor_conditional(current)
            && preprocessor_conditional_contains_descendant(current, node)
        {
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
            && !is_split_cpp_language_linkage_wrapper(conditional, node, source)
            && preprocessor_conditional_contains_descendant(conditional, node)
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
    if let Some(guard) = fragmented_statement_preprocessor_guard(node, source) {
        match guard {
            PreprocessorGuard::Constant(true) => {}
            PreprocessorGuard::Constant(false) => return None,
            _ => {
                if guards.contains(&guard.negated()) {
                    return None;
                }
                guards.insert(guard);
            }
        }
    }
    Some(guards)
}

fn fragmented_statement_preprocessor_guard(
    descendant: Node<'_>,
    source: &str,
) -> Option<PreprocessorGuard> {
    // A conditional that starts before `} else if (...) {` crosses the
    // enclosing statement's grammar boundary. tree-sitter leaves its opener
    // as a `preproc_if` with a missing terminator in the consequence and
    // reparses the real `#endif` as a `preproc_call` in the alternative. Pair
    // those structured nodes before restoring the guard to intervening uses.
    let mut ancestor = descendant.parent();
    while let Some(statement) = ancestor {
        if statement.kind() == "if_statement"
            && let (Some(consequence), Some(alternative)) = (
                statement.child_by_field_name("consequence"),
                statement.child_by_field_name("alternative"),
            )
            && alternative.start_byte() <= descendant.start_byte()
            && descendant.end_byte() <= alternative.end_byte()
        {
            let mut cursor = consequence.walk();
            let openers = consequence
                .named_children(&mut cursor)
                .filter(|child| {
                    matches!(child.kind(), "preproc_if" | "preproc_ifdef")
                        && child
                            .child(child.child_count().saturating_sub(1))
                            .is_some_and(|last| last.kind() == "#endif" && last.is_missing())
                })
                .collect::<Vec<_>>();
            if openers.len() != 1 {
                ancestor = statement.parent();
                continue;
            }

            let mut terminators = Vec::new();
            let mut stack = vec![alternative];
            while let Some(node) = stack.pop() {
                if node.kind() == "preproc_call"
                    && node.start_byte() >= descendant.end_byte()
                    && node
                        .child_by_field_name("directive")
                        .is_some_and(|directive| node_text(directive, source).trim() == "#endif")
                {
                    terminators.push(node);
                    continue;
                }
                for index in (0..node.named_child_count()).rev() {
                    if let Some(child) = node.named_child(index) {
                        stack.push(child);
                    }
                }
            }
            if terminators.len() == 1 {
                return simple_preprocessor_guard(openers[0], source);
            }
        }
        ancestor = statement.parent();
    }
    None
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

fn preprocessor_conditional_contains_descendant(
    conditional: Node<'_>,
    descendant: Node<'_>,
) -> bool {
    cpp_displaced_preprocessor_boundary(conditional)
        .is_none_or(|boundary| descendant.end_byte() <= boundary.end_byte)
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
        "identifier" => Some(PreprocessorGuard::Boolean(BooleanGuardExpression::Truthy(
            node_text(expression, source).to_string(),
        ))),
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
        "binary_expression" => Some(PreprocessorGuard::Boolean(boolean_preprocessor_expression(
            expression, source,
        ))),
        _ => None,
    }
}

fn boolean_preprocessor_expression(expression: Node<'_>, source: &str) -> BooleanGuardExpression {
    match expression.kind() {
        "number_literal" => match node_text(expression, source).trim() {
            "0" => BooleanGuardExpression::Constant(false),
            "1" => BooleanGuardExpression::Constant(true),
            _ => BooleanGuardExpression::Opaque(normalize_cpp_whitespace(node_text(
                expression, source,
            ))),
        },
        "identifier" => BooleanGuardExpression::Truthy(node_text(expression, source).to_string()),
        "preproc_defined" => {
            let identifier = (0..expression.named_child_count())
                .filter_map(|index| expression.named_child(index))
                .find(|child| child.kind() == "identifier");
            identifier.map_or_else(
                || {
                    BooleanGuardExpression::Opaque(normalize_cpp_whitespace(node_text(
                        expression, source,
                    )))
                },
                |identifier| {
                    BooleanGuardExpression::Defined(node_text(identifier, source).to_string())
                },
            )
        }
        "unary_expression"
            if expression
                .child_by_field_name("operator")
                .is_some_and(|operator| operator.kind() == "!") =>
        {
            expression.child_by_field_name("argument").map_or_else(
                || {
                    BooleanGuardExpression::Opaque(normalize_cpp_whitespace(node_text(
                        expression, source,
                    )))
                },
                |argument| boolean_preprocessor_expression(argument, source).negated(),
            )
        }
        "parenthesized_expression" => (0..expression.named_child_count())
            .filter_map(|index| expression.named_child(index))
            .next()
            .map_or_else(
                || {
                    BooleanGuardExpression::Opaque(normalize_cpp_whitespace(node_text(
                        expression, source,
                    )))
                },
                |child| boolean_preprocessor_expression(child, source),
            ),
        "binary_expression" => {
            let operands = || {
                Some((
                    boolean_preprocessor_expression(
                        expression.child_by_field_name("left")?,
                        source,
                    ),
                    boolean_preprocessor_expression(
                        expression.child_by_field_name("right")?,
                        source,
                    ),
                ))
            };
            match expression
                .child_by_field_name("operator")
                .map(|operator| operator.kind())
            {
                Some("&&") => operands().map_or_else(
                    || {
                        BooleanGuardExpression::Opaque(normalize_cpp_whitespace(node_text(
                            expression, source,
                        )))
                    },
                    |(left, right)| BooleanGuardExpression::all([left, right]),
                ),
                Some("||") => operands().map_or_else(
                    || {
                        BooleanGuardExpression::Opaque(normalize_cpp_whitespace(node_text(
                            expression, source,
                        )))
                    },
                    |(left, right)| BooleanGuardExpression::any([left, right]),
                ),
                _ => BooleanGuardExpression::Opaque(normalize_cpp_whitespace(node_text(
                    expression, source,
                ))),
            }
        }
        _ => {
            BooleanGuardExpression::Opaque(normalize_cpp_whitespace(node_text(expression, source)))
        }
    }
}

fn unique_include_target(mut targets: Vec<ProjectFile>) -> Option<ProjectFile> {
    if targets.len() == 1 {
        targets.pop()
    } else {
        None
    }
}

/// The declaration nodes of `candidate` in `prepared` that stand at a scope a
/// later reference can name.
///
/// A declaration inside a real function body, lambda, or nested block is block
/// local and is dropped. A declaration inside a parser-recovery wrapper that
/// merely looks callable -- an export macro between `class` and its name, or a
/// namespace-opening macro token before `namespace x {` -- keeps class or
/// namespace scope and is kept.
fn nameable_callable_declaration_nodes<'tree>(
    analyzer: &CppGraphSource<'_>,
    prepared: &'tree PreparedSyntaxTree,
    candidate: &CodeUnit,
) -> Vec<Node<'tree>> {
    let root = prepared.tree().root_node();
    analyzer
        .ranges(candidate)
        .into_iter()
        .filter_map(|range| {
            let mut declaration =
                root.descendant_for_byte_range(range.start_byte, range.end_byte)?;
            // A declaration an attribute-like macro invocation swallowed lives
            // inside the `ERROR` the parser left, not inside a `declaration`
            // node, so that envelope is where the climb stops (#2552).
            while !matches!(
                declaration.kind(),
                "declaration" | "field_declaration" | "function_definition"
            ) && !crate::declarations::is_macro_wrapped_declaration_envelope(
                declaration,
                prepared.source(),
            ) {
                declaration = declaration.parent()?;
            }
            let mut ancestor = declaration.parent();
            while let Some(node) = ancestor {
                if node.kind() == "function_definition"
                    && is_recovered_declaration_scope_container(node, prepared.source())
                {
                    ancestor = node.parent();
                    continue;
                }
                if node.kind() == "compound_statement"
                    && node.parent().is_some_and(|parent| {
                        is_recovered_declaration_scope_container(parent, prepared.source())
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
            Some(declaration)
        })
        .collect()
}

fn callable_declaration_activation_in_file(
    analyzer: &CppGraphSource<'_>,
    prepared: &PreparedSyntaxTree,
    candidate: &CodeUnit,
    reference: &CallableReferenceContext<'_>,
) -> Option<usize> {
    nameable_callable_declaration_nodes(analyzer, prepared, candidate)
        .into_iter()
        .filter(|declaration| {
            callable_preprocessor_context_is_visible_for_reference(
                *declaration,
                prepared.source(),
                reference,
            )
        })
        .map(callable_declaration_activation_byte)
        .min()
}

/// C and C++ activate a declared name at the end of its declarator, not at the
/// end of the whole declaration. A function definition ends at the closing
/// brace of its body, so the declaration end byte would hide the function from
/// its own body and make self recursion unresolvable without a prototype.
fn callable_declaration_activation_byte(declaration: Node<'_>) -> usize {
    if declaration.kind() != "function_definition" {
        return declaration.end_byte();
    }
    declaration
        .child_by_field_name("declarator")
        .map_or(declaration.end_byte(), |declarator| declarator.end_byte())
}

/// The reference side of a callable visibility question.
///
/// An include-graph walk and a whole-file arity activation ask the question
/// without one reference position, so they carry no `position` and therefore no
/// guard environment.
struct CallableReferenceContext<'a> {
    file: &'a ProjectFile,
    position: Option<CallableReferencePosition<'a>>,
}

/// One reference position plus its preprocessor guard environment. The
/// environment is computed on demand because most declarations carry no
/// non-trivial guard.
struct CallableReferencePosition<'a> {
    prepared: &'a PreparedSyntaxTree,
    byte: usize,
    guards: &'a OnceCell<Option<HashSet<PreprocessorGuard>>>,
}

impl CallableReferenceContext<'_> {
    fn is_c(&self) -> bool {
        self.file
            .rel_path()
            .extension()
            .and_then(|extension| extension.to_str())
            == Some("c")
    }

    fn guards(&self) -> Option<&HashSet<PreprocessorGuard>> {
        let position = self.position.as_ref()?;
        position
            .guards
            .get_or_init(|| {
                position
                    .prepared
                    .tree()
                    .root_node()
                    .descendant_for_byte_range(position.byte, position.byte.saturating_add(1))
                    .and_then(|node| {
                        preprocessor_guard_environment(node, position.prepared.source())
                    })
            })
            .as_ref()
    }
}

fn callable_preprocessor_context_is_visible_for_reference(
    node: Node<'_>,
    source: &str,
    reference: &CallableReferenceContext<'_>,
) -> bool {
    let reference_is_c = reference.is_c();
    let mut ancestor = node.parent();
    while let Some(conditional) = ancestor {
        if matches!(conditional.kind(), "preproc_if" | "preproc_ifdef")
            && !is_file_covering_include_guard(conditional, source)
            && !is_split_cpp_language_linkage_wrapper(conditional, node, source)
            && preprocessor_conditional_contains_descendant(conditional, node)
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
                // The declaration stands under a guard whose value this
                // analyzer cannot decide. It is still co-active with a
                // reference whose active guards imply it. Collecting one guard
                // per ancestor makes the whole walk a conjunction of the
                // declaration requirements.
                guard => {
                    if !reference
                        .guards()
                        .is_some_and(|active| preprocessor_guard_holds_at_reference(&guard, active))
                    {
                        return false;
                    }
                }
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

    let Some(prepared) = cpp.prepared_syntax(analyzer.token, visible_declaration.source()) else {
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
    let function = body.parent()?;
    if function.child_by_field_name("body") != Some(body) {
        return None;
    }
    let namespace_name = recovered_macro_namespace_name(function, source)?;
    let mut components = enclosing_namespace_components(declaration, source)?;
    components.push(namespace_name);
    Some(components)
}

/// The namespace name a namespace-opening macro token displaced into a
/// synthetic `function_definition`, or `None` when `function` is not that
/// recovery shape.
///
/// `ABSL_NAMESPACE_BEGIN` (or `FMT_BEGIN_NAMESPACE`, ...) immediately before
/// `namespace x {` leaves tree-sitter with a `function_definition` whose type is
/// the macro token, whose declarator is the namespace name behind an `ERROR`
/// holding the `namespace` keyword, and whose body spans the whole namespace
/// region. The matching `*_NAMESPACE_END` sibling is what separates the recovery
/// artifact from a real function definition.
fn recovered_macro_namespace_name(function: Node<'_>, source: &str) -> Option<String> {
    if function.kind() != "function_definition" || !function.has_error() {
        return None;
    }
    let body = function
        .child_by_field_name("body")
        .filter(|body| body.kind() == "compound_statement")?;
    let mut cursor = function.walk();
    let prefix = function
        .named_children(&mut cursor)
        .take_while(|child| child.start_byte() < body.start_byte())
        .filter(|child| child.kind() != "comment")
        .collect::<Vec<_>>();
    let begin_index = prefix.iter().rposition(|child| {
        flattened_macro_sentinel_name(*child, source)
            .is_some_and(|name| is_namespace_begin_sentinel(&name))
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
    flattened_macro_sentinel_name(next, source)
        .is_some_and(|name| is_namespace_end_sentinel(&name))
        .then(|| namespace_name.clone())
}

/// A `function_definition` that exists only because tree-sitter recovered a
/// macro-decorated class head or a namespace-opening macro token. A declaration
/// in such a body keeps class or namespace scope, so a scope walk must step over
/// the wrapper instead of treating the declaration as block local.
fn is_recovered_declaration_scope_container(node: Node<'_>, source: &str) -> bool {
    crate::declarations::is_recovered_exported_class_container(node, source)
        || recovered_macro_namespace_name(node, source).is_some()
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
            .is_some_and(|name| is_namespace_begin_sentinel(&name))
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
            is_namespace_begin_sentinel(&name) || is_namespace_end_sentinel(&name)
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
            .is_some_and(|name| is_namespace_end_sentinel(&name))
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
    // At translation-unit scope the trailing `X_NAMESPACE_END` token parses as
    // an `expression_statement` with a missing semicolon; inside a namespace
    // body the same token stays a bare `type_identifier`.
    let node = if node.kind() == "expression_statement" && node.named_child_count() == 1 {
        node.named_child(0)?
    } else {
        node
    };
    let candidate = direct_cpp_identifier_name(node, source).or_else(|| {
        node.child_by_field_name("type")
            .and_then(|type_node| direct_cpp_identifier_name(type_node, source))
    })?;
    (cpp_export_macro_token(&candidate)
        && (is_namespace_begin_sentinel(&candidate) || is_namespace_end_sentinel(&candidate)))
    .then_some(candidate)
}

/// Namespace-opening macros are spelled both ways in the wild:
/// `ABSL_NAMESPACE_BEGIN` (abseil, nlohmann) and `FMT_BEGIN_NAMESPACE` (fmt).
fn is_namespace_begin_sentinel(name: &str) -> bool {
    name.ends_with("NAMESPACE_BEGIN") || name.ends_with("BEGIN_NAMESPACE")
}

fn is_namespace_end_sentinel(name: &str) -> bool {
    name.ends_with("NAMESPACE_END") || name.ends_with("END_NAMESPACE")
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
    if conditional.child_by_field_name("alternative").is_some()
        || !matches!(
            simple_preprocessor_guard(conditional, source),
            Some(PreprocessorGuard::Defined(name)) if name == "__cplusplus"
        )
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
            matches!(
                simple_preprocessor_guard(child, source),
                Some(PreprocessorGuard::Defined(name)) if name == "__cplusplus"
            ) && (0..child.child_count()).any(|index| {
                child
                    .child(index)
                    .is_some_and(|token| token.kind() == "#endif" && token.is_missing())
            })
        });
    closes_opening_branch && reopens_for_closing_brace
}

/// The argument list a call-shaped node supplies: `f(args)`, `new T(args)`,
/// `T{args}` and the member initializer `: field(args)`, whose grammar gives its
/// argument list no field name.
pub fn call_arguments_node(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("arguments")
        .or_else(|| node.child_by_field_name("parameters"))
        .or_else(|| node.child_by_field_name("value"))
        .or_else(|| first_named_child_of_kind(node, "argument_list"))
        .or_else(|| first_named_child_of_kind(node, "initializer_list"))
}

pub fn call_arity(node: Node<'_>) -> usize {
    call_arguments_node(node)
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

fn recovered_c_keyword_argument_count(
    file: &ProjectFile,
    call: Node<'_>,
    arguments: Node<'_>,
    source: &str,
) -> usize {
    // A C identifier that is a C++ keyword can be displaced twice by the C++
    // grammar: first into a direct parameter-list `ERROR(keyword)`, then into
    // a direct argument-list `ERROR(',', keyword)`. Match those CST tokens in
    // the enclosing C function before restoring the otherwise dropped slot.
    if !is_c_source_file(file) || arguments.kind() != "argument_list" {
        return 0;
    }
    let mut ancestor = Some(call);
    let function = loop {
        let Some(current) = ancestor else {
            return 0;
        };
        if current.kind() == "function_definition" {
            break current;
        }
        ancestor = current.parent();
    };
    let Some(parameters) = function
        .child_by_field_name("declarator")
        .and_then(|declarator| declarator.child_by_field_name("parameters"))
    else {
        return 0;
    };
    let displaced_parameter_keywords = (0..parameters.child_count())
        .filter_map(|index| parameters.child(index))
        .filter(|error| error.kind() == "ERROR")
        .filter_map(|error| {
            let parameter = error.prev_named_sibling()?;
            if parameter.kind() != "parameter_declaration"
                || parameter.end_byte() != error.start_byte()
                || extract_variable_name(parameter, source).is_some()
            {
                return None;
            }
            let mut children = (0..error.child_count())
                .filter_map(|index| error.child(index))
                .filter(|child| !child.is_extra() && !child.is_missing());
            let keyword = children.next()?;
            (children.next().is_none() && !keyword.is_named() && keyword.child_count() == 0)
                .then_some(keyword)
        })
        .collect::<Vec<_>>();
    if displaced_parameter_keywords.is_empty() {
        return 0;
    }

    (0..arguments.child_count())
        .filter_map(|index| arguments.child(index))
        .filter(|error| error.kind() == "ERROR" && error.is_extra())
        .filter(|error| {
            let mut children = (0..error.child_count())
                .filter_map(|index| error.child(index))
                .filter(|child| !child.is_extra() && !child.is_missing());
            let Some(comma) = children.next() else {
                return false;
            };
            let Some(keyword) = children.next() else {
                return false;
            };
            children.next().is_none()
                && comma.kind() == ","
                && !keyword.is_named()
                && keyword.child_count() == 0
                && displaced_parameter_keywords
                    .iter()
                    .any(|parameter| parameter.kind_id() == keyword.kind_id())
        })
        .count()
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

/// The one logical type the candidates name, or why they do not name one.
fn logical_type_candidate(candidates: Vec<&CodeUnit>) -> Result<CodeUnit, TypeCandidateFailure> {
    let Some(first) = candidates.first() else {
        return Err(TypeCandidateFailure::Unresolvable);
    };
    if candidates
        .iter()
        .all(|candidate| candidate.kind() == first.kind() && candidate.fq_name() == first.fq_name())
    {
        Ok((*first).clone())
    } else {
        Err(TypeCandidateFailure::Ambiguous)
    }
}

fn unique_logical_type_candidate(candidates: Vec<&CodeUnit>) -> Option<CodeUnit> {
    logical_type_candidate(candidates).ok()
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
                declared_type_alias(analyzer, candidate)
                    && candidate.kind() == first.kind()
                    && candidate.fq_name() == first.fq_name()
                    && candidate.source() == first.source()
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
            let declared_type = if matches!(
                type_node.kind(),
                "class_specifier" | "struct_specifier" | "union_specifier"
            ) {
                type_node.child_by_field_name("name")
            } else {
                Some(type_node)
            };
            let type_text = declared_type.map_or_else(
                || field.identifier().to_string(),
                |declared_type| node_text(declared_type, &declaration).to_string(),
            );
            return Some(DeclaredFieldTypeFact {
                type_text,
                indirection,
                template_arguments: declared_type.and_then(|declared_type| {
                    cpp_template_reference_arguments(declared_type, &declaration)
                }),
            });
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    None
}

/// Text of the type that a C or C++ alias declaration names, read from the
/// `type_definition` or `alias_declaration` node's `type` field.
///
/// The declaration text is never scanned. A function-pointer typedef
/// interleaves its aliased type with its declarator (`typedef R (*F)(int)`),
/// so no prefix or suffix of the spelling isolates the target.
///
/// An alias whose declarator is a function declarator names a function type:
/// `typedef R F(int)`, `typedef R (*F)(int)`, `typedef R *F(int)`, and
/// `using F = R (*)(int)`. The analyzer's type model names declared types only,
/// so such an alias has no canonical target. Its `type` field holds the return
/// type `R`, which is a different type from the alias, so this returns `None`
/// rather than that return type.
pub fn cpp_alias_declaration_target_text(declaration: &str) -> Option<String> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_cpp::LANGUAGE.into())
        .ok()?;
    let tree = parser.parse(declaration, None)?;
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        let type_node = match node.kind() {
            "type_definition" => {
                let mut cursor = node.walk();
                if node
                    .children_by_field_name("declarator", &mut cursor)
                    .any(declarator_names_function_type)
                {
                    return None;
                }
                node.child_by_field_name("type")?
            }
            "alias_declaration" => {
                let type_node = node.child_by_field_name("type")?;
                if type_node
                    .child_by_field_name("declarator")
                    .is_some_and(declarator_names_function_type)
                {
                    return None;
                }
                type_node
            }
            _ => {
                let mut cursor = node.walk();
                let children = node.named_children(&mut cursor).collect::<Vec<_>>();
                stack.extend(children.into_iter().rev());
                continue;
            }
        };
        return Some(node_text(type_node, declaration).to_string());
    }
    None
}

/// Whether an alias declaration's own declarator adds indirection that
/// [`cpp_alias_declaration_target_text`] does not report.
///
/// That function reads the declaration's `type` field, where `typedef Foo *Bar`
/// keeps only `Foo`: the `*` lives in the sibling declarator. Substituting such
/// an alias would equate `f(Bar)` with `f(Foo)`, so a comparison that cannot
/// prove the alias adds no indirection must refuse to follow it. A declaration
/// this cannot read at all is refused for the same reason.
fn cpp_alias_declaration_adds_indirection(declaration: &str) -> bool {
    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_cpp::LANGUAGE.into())
        .is_err()
    {
        return true;
    }
    let Some(tree) = parser.parse(declaration, None) else {
        return true;
    };
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        let declarators = match node.kind() {
            "type_definition" => {
                let mut cursor = node.walk();
                node.children_by_field_name("declarator", &mut cursor)
                    .collect::<Vec<_>>()
            }
            "alias_declaration" => node
                .child_by_field_name("type")
                .and_then(|type_node| type_node.child_by_field_name("declarator"))
                .into_iter()
                .collect::<Vec<_>>(),
            _ => {
                let mut cursor = node.walk();
                let children = node.named_children(&mut cursor).collect::<Vec<_>>();
                stack.extend(children.into_iter().rev());
                continue;
            }
        };
        return declarators.into_iter().any(cpp_declarator_adds_indirection);
    }
    true
}

/// True when an alias declarator names a function type.
///
/// The declarator chain is walked through the `declarator` field, so the
/// parameter list -- a sibling field -- is never entered and a parameter's own
/// function declarator cannot be mistaken for the alias's.
fn declarator_names_function_type(declarator: Node<'_>) -> bool {
    let mut current = Some(declarator);
    while let Some(node) = current {
        match node.kind() {
            "function_declarator" | "abstract_function_declarator" => return true,
            "parenthesized_declarator" | "abstract_parenthesized_declarator" => {
                current = node.named_child(0);
            }
            _ => current = node.child_by_field_name("declarator"),
        }
    }
    false
}

/// Whether one indexed field declaration is a function or function-pointer
/// value. This follows tree-sitter declarator fields and never infers
/// callability from source spelling.
pub fn cpp_field_declaration_names_function_type(declaration: &str, field_name: &str) -> bool {
    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_cpp::LANGUAGE.into())
        .is_err()
    {
        return false;
    }
    let Some(tree) = parser.parse(declaration, None) else {
        return false;
    };
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if matches!(node.kind(), "declaration" | "field_declaration") {
            let mut cursor = node.walk();
            if node
                .children_by_field_name("declarator", &mut cursor)
                .any(|declarator| {
                    declarator_name_node(declarator).is_some_and(|name| {
                        node_text(name, declaration) == field_name
                            && declarator_names_function_type(declarator)
                    })
                })
            {
                return true;
            }
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    false
}

/// Whether one indexed alias declaration names a function or function-pointer
/// type. The alias name is matched through the declarator field so a function
/// type used by a parameter cannot be mistaken for the alias itself.
pub fn cpp_alias_declaration_names_function_type(declaration: &str, alias_name: &str) -> bool {
    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_cpp::LANGUAGE.into())
        .is_err()
    {
        return false;
    }
    let Some(tree) = parser.parse(declaration, None) else {
        return false;
    };
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "type_definition" => {
                let mut cursor = node.walk();
                if node
                    .children_by_field_name("declarator", &mut cursor)
                    .any(|declarator| {
                        extract_typedef_declarator_name(declarator, declaration)
                            .is_some_and(|name| name == alias_name)
                            && declarator_names_function_type(declarator)
                    })
                {
                    return true;
                }
            }
            "alias_declaration" => {
                let names_alias = node
                    .child_by_field_name("name")
                    .is_some_and(|name| node_text(name, declaration) == alias_name);
                if names_alias
                    && node
                        .child_by_field_name("type")
                        .and_then(|type_node| type_node.child_by_field_name("declarator"))
                        .is_some_and(declarator_names_function_type)
                {
                    return true;
                }
            }
            _ => {}
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    false
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
                let declarator = node
                    .children_by_field_name("declarator", &mut declarator_cursor)
                    .find(|declarator| {
                        extract_typedef_declarator_name(*declarator, declaration)
                            .is_some_and(|name| name == unit.identifier())
                    })?;
                if declarator_names_function_type(declarator) {
                    return None;
                }
                node.child_by_field_name("type")?
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
                if node_text(name, declaration) != unit.identifier() {
                    return None;
                }
                let type_node = node.child_by_field_name("type")?;
                if type_node
                    .child_by_field_name("declarator")
                    .is_some_and(declarator_names_function_type)
                {
                    return None;
                }
                type_node
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

/// How a `T var ...;` declaration initializes its object.
pub enum DeclarationConstructorInitializer<'tree> {
    /// Direct initialization, `T var(args)` or `T var{args}`: the argument list
    /// the declaration hands the constructor.
    Arguments(Node<'tree>),
    /// Copy initialization from one expression, `T var = expr`, which supplies a
    /// single constructor argument without spelling an argument list.
    Expression(Node<'tree>),
    /// `T var;`, which names no constructor argument at all.
    Empty,
}

pub fn declaration_constructor_initializer(
    node: Node<'_>,
) -> DeclarationConstructorInitializer<'_> {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() == "init_declarator" {
            let Some(value) = child
                .child_by_field_name("value")
                .or_else(|| first_named_child_of_kind(child, "initializer_list"))
                .or_else(|| first_named_child_of_kind(child, "compound_literal_expression"))
            else {
                return DeclarationConstructorInitializer::Empty;
            };
            return match value.kind() {
                "argument_list" | "initializer_list" => {
                    DeclarationConstructorInitializer::Arguments(value)
                }
                "compound_literal_expression" => call_arguments_node(value)
                    .map_or(DeclarationConstructorInitializer::Empty, |arguments| {
                        DeclarationConstructorInitializer::Arguments(arguments)
                    }),
                _ => DeclarationConstructorInitializer::Expression(value),
            };
        }
        if is_declarator_node(child) {
            return declarator_parameters(child)
                .map_or(DeclarationConstructorInitializer::Empty, |parameters| {
                    DeclarationConstructorInitializer::Arguments(parameters)
                });
        }
    }
    DeclarationConstructorInitializer::Empty
}

pub fn declaration_constructor_arity(node: Node<'_>, _ctx: &ScanCtx<'_>) -> usize {
    match declaration_constructor_initializer(node) {
        DeclarationConstructorInitializer::Arguments(arguments) => {
            argument_children(arguments).count()
        }
        DeclarationConstructorInitializer::Expression(_) => 1,
        DeclarationConstructorInitializer::Empty => 0,
    }
}

/// The parameter list of the innermost declarator, which is where a
/// `T var(args)` declaration parsed as a function declarator keeps the
/// constructor arguments.
fn declarator_parameters(node: Node<'_>) -> Option<Node<'_>> {
    let mut current = node;
    loop {
        if let Some(parameters) = current.child_by_field_name("parameters") {
            return Some(parameters);
        }
        current = current.child_by_field_name("declarator")?;
    }
}

pub(super) fn first_named_child_of_kind<'tree>(
    node: Node<'tree>,
    kind: &str,
) -> Option<Node<'tree>> {
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
    let descendant = node;
    while let Some(parent) = node.parent() {
        if is_preprocessor_conditional(parent)
            && !is_file_covering_include_guard(parent, source)
            && preprocessor_conditional_contains_descendant(parent, descendant)
        {
            return true;
        }
        node = parent;
    }
    false
}

/// The [`OwningPreprocessorConditionals`] of a macro event at `event`.
///
/// The descendant this walks up from is the one
/// [`VisibilityIndex::macro_event_condition_value`] starts from -- the
/// innermost node at the event's first byte, not the event node itself --
/// because containment compares that descendant's end against the recovered
/// conditional boundary, and the two nodes end in different places. An event
/// that [`has_preprocessor_conditional_ancestor`] rejects owns nothing: that
/// predicate is what has always decided whether an event is conditional at
/// all, and answering it first also skips the walk for the ordinary
/// unconditional event.
fn owning_preprocessor_conditionals(
    root: Node<'_>,
    event: Node<'_>,
    source: &str,
) -> OwningPreprocessorConditionals {
    if !has_preprocessor_conditional_ancestor(event, source) {
        return OwningPreprocessorConditionals::default();
    }
    let start = event.start_byte();
    let descendant = root
        .descendant_for_byte_range(start, start.saturating_add(1).min(source.len()))
        .expect("a byte inside the parsed tree names a descendant");
    let mut owners = Vec::new();
    let mut current = descendant.parent();
    while let Some(conditional) = current {
        if is_preprocessor_conditional(conditional)
            && !is_file_covering_include_guard(conditional, source)
            && preprocessor_conditional_contains_descendant(conditional, descendant)
        {
            owners.push(conditional.start_byte());
        }
        current = conditional.parent();
    }
    owners.into_boxed_slice()
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

/// Whether `file` is proven to use plain-C source semantics.
///
/// `Language::Cpp` intentionally serves both C and C++. Headers do not carry a
/// compilation dialect on their own, so only an exact `.c` source extension is
/// sufficient to reinterpret C++-grammar keyword nodes such as `this` as C
/// identifiers.
///
/// The exact-lowercase-`.c` rule itself lives in [`LanguageDialect::for_path`],
/// which extraction reads too (a `.c` file is extracted with C tag scope), so
/// the doctrine has exactly one definition.
pub fn is_c_source_file(file: &ProjectFile) -> bool {
    LanguageDialect::for_path(Language::Cpp, file.rel_path()) == LanguageDialect::CppC
}

/// Whether tree-sitter parsed the operand of C `sizeof(T)` as an expression
/// identifier even though `T` may denote a typedef.
///
/// The grammar cannot distinguish `sizeof(value)` from `sizeof(Type)` without
/// semantic information. Keep this helper structural and narrow; callers must
/// still prove a visible type and reject an active ordinary-namespace shadow.
pub fn is_c_sizeof_expression_type_candidate(file: &ProjectFile, node: Node<'_>) -> bool {
    if !is_c_source_file(file) || node.kind() != "identifier" {
        return false;
    }
    let mut operand = node;
    while let Some(parent) = operand.parent().filter(|parent| {
        parent.kind() == "parenthesized_expression"
            && parent.named_child_count() == 1
            && parent.named_child(0) == Some(operand)
    }) {
        operand = parent;
    }
    operand.parent().is_some_and(|parent| {
        parent.kind() == "sizeof_expression" && parent.child_by_field_name("value") == Some(operand)
    })
}

/// Whether `node` is a template argument name that tree-sitter spelled with
/// type syntax.
///
/// The grammar cannot tell a type argument from a non-type (value) argument, so
/// it gives both the same shape:
/// `template_argument_list -> type_descriptor -> type_identifier`. In
/// `std::array<W, N>` the type `W` and the constant `N` parse identically, and
/// so do `std::span<const uint8_t, ED448_LEN>`'s length and a nested type
/// member used as a real type argument.
///
/// This helper reports only the syntactic position. A caller must still prove
/// which namespace explains the spelling: forward navigation asks the type
/// namespace first and reads the leaf as a value only when no type explains it,
/// and the inverse field scan admits the leaf only when no visible type does
/// (#2556).
pub fn is_type_shaped_template_argument_name(node: Node<'_>) -> bool {
    if node.kind() != "type_identifier" {
        return false;
    }
    let Some(descriptor) = node
        .parent()
        .filter(|parent| parent.kind() == "type_descriptor")
    else {
        return false;
    };
    if descriptor.child_by_field_name("type") != Some(node) {
        return false;
    }
    let Some(arguments) = descriptor
        .parent()
        .filter(|parent| parent.kind() == "template_argument_list")
    else {
        return false;
    };
    arguments.parent().is_some_and(|owner| {
        matches!(
            owner.kind(),
            "template_type" | "template_function" | "template_method"
        ) && owner.child_by_field_name("arguments") == Some(arguments)
    })
}

/// Whether a reference written in `file` reads C++ source with C semantics.
///
/// [`is_c_source_file`] answers the half a path settles on its own. The other
/// half is a header, which has no dialect of its own: it is read as C exactly
/// when every workspace translation unit that provably compiles it compiles it
/// as C ([`CppSource::header_uses_c_semantics`], issue #1970).
///
/// This is the gate for anything that is really about the compilation
/// language of the code being read -- which reading of an included header's
/// declarations is in scope, whether `this` is an ordinary identifier. It is
/// NOT the gate for a question that is genuinely about a `.c` file on disk;
/// those keep calling [`is_c_source_file`].
pub fn reference_uses_c_semantics(cpp: &dyn CppSource, file: &ProjectFile) -> bool {
    is_c_source_file(file) || cpp.header_uses_c_semantics(file)
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

/// One run of a container's children that tree-sitter parsed outside the
/// namespaces that really enclose it, with the namespaces that do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveredNamespaceRegion {
    /// Start byte of the first child in the run.
    pub start: usize,
    /// End byte of the last child in the run.
    pub end: usize,
    /// The complete enclosing namespace path of the run, outermost first: the
    /// namespaces the parse tree still attributes to the container, then the
    /// ones recovery dropped.
    pub components: Vec<String>,
}

/// The namespaces C++ parse recovery drops from a file's tree.
///
/// When tree-sitter cannot parse a construct inside a namespace body it closes
/// an inner scope with a MISSING brace, or skips an opening brace into an
/// ERROR node. Every real `}` after that then closes one scope too early: a
/// class body's `}` closes the namespace, the namespace's own `}` closes its
/// parent, and the outermost real closes land in a trailing ERROR node. The
/// declarations between a stolen close and the real one keep their byte
/// positions but lose their `namespace_definition` ancestors (Catch2's
/// `catch_matchers_templated.hpp`, issue #1537).
///
/// Braces balance in source that compiles, so the lost scopes are exactly what
/// a brace stack over tree-sitter's own tokens leaves open. Within one node, in
/// child order: a real `{` opens a scope (the node's namespace when the node is
/// a named namespace body, otherwise an opaque scope); a real `}` closes the
/// innermost open scope, or is owed to the parent when the node has none open;
/// a MISSING brace is not a token and does nothing; a child without errors is
/// balanced and contributes nothing; an error-marked child contributes the
/// closes it owes and the scopes it leaves open. Whatever is open before a
/// child starts, beyond the node's own scope, is what the parse lost for that
/// child. Consecutive children with the same lost namespaces form one
/// [`RecoveredNamespaceRegion`]. A file without parse errors has no regions.
#[derive(Clone, Debug, Default)]
pub struct OrphanedNamespaceScopeIndex {
    regions: Vec<RecoveredNamespaceRegion>,
}

impl OrphanedNamespaceScopeIndex {
    pub fn build(root: Node<'_>, source: &str) -> Self {
        if !root.has_error() {
            return Self::default();
        }
        struct Frame<'tree> {
            node: Node<'tree>,
            children: std::vec::IntoIter<Node<'tree>>,
            /// The enclosing namespace path of this node's children before
            /// this node's own scopes: the parent's path plus what was open in
            /// the parent when this node started.
            scope: Vec<String>,
            /// The namespace this node's own real `{` opens; empty when the
            /// node is not a named namespace body.
            own_scope: Vec<String>,
            /// Scopes opened inside this node and still open, innermost last.
            /// A namespace carries its name components; an opaque scope (a
            /// class body, a function body, a brace inside an ERROR) is empty.
            open: Vec<Vec<String>>,
            /// Whether `open[0]` is this node's own scope.
            own_open: bool,
            /// Real closes seen with nothing open here; the parent closes them.
            owed: usize,
            /// The run of children currently sharing the same lost namespaces.
            run: Option<RecoveredNamespaceRegion>,
        }
        fn frame<'tree>(
            node: Node<'tree>,
            scope: Vec<String>,
            own_scope: Vec<String>,
        ) -> Frame<'tree> {
            let mut cursor = node.walk();
            let children = node.children(&mut cursor).collect::<Vec<_>>().into_iter();
            Frame {
                node,
                children,
                scope,
                own_scope,
                open: Vec::new(),
                own_open: false,
                owed: 0,
                run: None,
            }
        }
        let mut regions = Vec::new();
        let mut frames = vec![frame(root, Vec::new(), Vec::new())];
        while let Some(current) = frames.last_mut() {
            let Some(child) = current.children.next() else {
                let done = frames.pop().expect("the frame just borrowed");
                regions.extend(done.run);
                let Some(parent) = frames.last_mut() else {
                    break;
                };
                for _ in 0..done.owed {
                    if parent.open.pop().is_none() {
                        parent.owed += 1;
                    }
                }
                parent.own_open &= !parent.open.is_empty();
                parent.open.extend(done.open);
                continue;
            };
            match child.kind() {
                "{" if !child.is_missing() => {
                    let own = current.open.is_empty();
                    current.open.push(if own {
                        current.own_scope.clone()
                    } else {
                        Vec::new()
                    });
                    current.own_open |= own;
                    continue;
                }
                "}" if !child.is_missing() => {
                    if current.open.pop().is_none() {
                        current.owed += 1;
                    }
                    // The node's own close, or a close that reached it once
                    // every lost scope was popped: nothing of this node's is
                    // open for the children that follow.
                    current.own_open &= !current.open.is_empty();
                    continue;
                }
                _ => {}
            }
            let lost = &current.open[usize::from(current.own_open)..];
            let child_scope = current
                .scope
                .iter()
                .chain(current.open.iter().flatten())
                .cloned()
                .collect::<Vec<_>>();
            if lost.iter().any(|scope| !scope.is_empty()) {
                match &mut current.run {
                    Some(run) if run.components == child_scope => run.end = child.end_byte(),
                    run => {
                        regions.extend(run.take());
                        *run = Some(RecoveredNamespaceRegion {
                            start: child.start_byte(),
                            end: child.end_byte(),
                            components: child_scope.clone(),
                        });
                    }
                }
            } else {
                regions.extend(current.run.take());
            }
            if child.has_error() {
                let own_scope = namespace_body_name_components(current.node, child, source);
                frames.push(frame(child, child_scope, own_scope));
            }
        }
        Self { regions }
    }

    pub fn is_empty(&self) -> bool {
        self.regions.is_empty()
    }

    /// The bytes this index holds, for the analyzer cache's weight.
    pub fn approximate_size(&self) -> usize {
        self.regions.iter().fold(0usize, |total, region| {
            total
                .saturating_add(std::mem::size_of::<RecoveredNamespaceRegion>())
                .saturating_add(region.components.iter().map(String::len).sum::<usize>())
        })
    }

    /// The innermost recovered region containing `byte`.
    pub fn region_at(&self, byte: usize) -> Option<&RecoveredNamespaceRegion> {
        self.regions
            .iter()
            .filter(|region| region.start <= byte && byte < region.end)
            .min_by_key(|region| region.end - region.start)
    }

    /// The enclosing namespaces of `node`, outermost first, restoring the ones
    /// parse recovery dropped from its ancestor chain. The one answer both
    /// lookup directions and declaration collection use (issue #1537).
    pub fn enclosing_namespace_components(&self, node: Node<'_>, source: &str) -> Vec<String> {
        let mut parsed = Vec::new();
        let mut current = node.parent();
        while let Some(parent) = current {
            if parent.kind() == "namespace_definition"
                && let Some(name) = parent.child_by_field_name("name")
            {
                let mut components = Vec::new();
                if append_cpp_name_components(name, source, &mut components).is_some() {
                    parsed.push((parent.start_byte(), components));
                }
            }
            current = parent.parent();
        }
        parsed.reverse();
        self.restore_enclosing_namespaces(parsed, node.start_byte())
    }

    /// [`Self::enclosing_namespace_components`] for a caller that has already
    /// climbed the ancestor chain: `parsed` lists the node's named
    /// `namespace_definition` ancestors outermost first, each with its start
    /// byte. A region covering the node supplies every namespace outside it;
    /// only the parsed ancestors that start inside the region still apply.
    pub fn restore_enclosing_namespaces(
        &self,
        parsed: Vec<(usize, Vec<String>)>,
        node_start: usize,
    ) -> Vec<String> {
        let Some(region) = self.region_at(node_start) else {
            return parsed
                .into_iter()
                .flat_map(|(_, components)| components)
                .collect();
        };
        region
            .components
            .iter()
            .cloned()
            .chain(
                parsed
                    .into_iter()
                    .filter(|(start, _)| *start >= region.start)
                    .flat_map(|(_, components)| components),
            )
            .collect()
    }
}

/// The name components of the namespace whose body `body` is, or empty when
/// `body` is not the body of a named `namespace_definition` `parent`.
fn namespace_body_name_components(parent: Node<'_>, body: Node<'_>, source: &str) -> Vec<String> {
    let mut components = Vec::new();
    if body.kind() == "declaration_list"
        && parent.kind() == "namespace_definition"
        && parent.child_by_field_name("body") == Some(body)
        && let Some(name) = parent.child_by_field_name("name")
        && append_cpp_name_components(name, source, &mut components).is_none()
    {
        components.clear();
    }
    components
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveredDeclaratorTypeContext {
    Declaration,
    FunctionDefinition,
    Parameter,
}

/// Recognize a real type displaced into a qualified declarator by parser
/// recovery.
///
/// Tree-sitter parses `API Result *make(Arg);` as if `API` were the declared
/// type and `Result` were the scope of a qualified declarator with a missing
/// `::`. A template return such as `API Result<T> make()` uses a
/// `template_type` for the same recovered scope. The same recovery occurs for
/// macro-prefixed definitions, extern variables, and macro-decorated
/// parameters (`f(MACRO T* p)`, where the parameter's own `type` field takes
/// the macro). Keep this intentionally structural: the recovered scope must
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
    if !matches!(node.kind(), "namespace_identifier" | "template_type") || node.is_missing() {
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
        // `f(MACRO T* p)` recovers exactly like `MACRO T *make(...)` does, one
        // level down: the parameter's `type` field takes the macro token and
        // the real type `T` becomes the recovered scope of the declarator.
        // Declining here left every xxhash `XXH_NOESCAPE` parameter with no
        // candidate at all (#1830).
        if matches!(
            parent.kind(),
            "parameter_declaration" | "optional_parameter_declaration"
        ) && has_field_child(parent, "declarator", declarator)
        {
            return Some((parent, RecoveredDeclaratorTypeContext::Parameter));
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
            "identifier" | "field_identifier" | "type_identifier" | "operator_name" => {
                return true;
            }
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
    if text
        .chars()
        .all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
        && bindings.is_shadowed(text)
    {
        return true;
    }

    let Some(base) = parameter
        .child_by_field_name("type")
        .filter(|base| base.kind() == "type_identifier")
    else {
        return false;
    };
    let Some(subscript) = parameter
        .child_by_field_name("declarator")
        .filter(|declarator| declarator.kind() == "abstract_array_declarator")
    else {
        return false;
    };
    subscript.child_by_field_name("size").is_some()
        && bindings.is_shadowed(node_text(base, source).trim())
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

/// Whether tree-sitter recovered a qualified friend-class type as an ordinary
/// declaration's declarator inside a malformed class body.
///
/// An export macro between `class` and the class name can make the containing
/// body parse as a function body. A source declaration such as
/// `friend class internal::Friend;` then retains this exact structure:
/// `declaration(type: friend, ERROR(class), declarator: internal::Friend)`.
/// The declarator is a type reference despite its field role.
pub fn is_recovered_qualified_friend_class_type_reference(node: Node<'_>, source: &str) -> bool {
    if !matches!(
        node.kind(),
        "qualified_identifier" | "scoped_type_identifier"
    ) {
        return false;
    }
    let Some(declaration) = node
        .parent()
        .filter(|parent| parent.kind() == "declaration")
    else {
        return false;
    };
    if declaration.child_by_field_name("declarator") != Some(node)
        || !declaration
            .child_by_field_name("type")
            .is_some_and(|friend| {
                friend.kind() == "type_identifier" && node_text(friend, source) == "friend"
            })
    {
        return false;
    }
    let mut cursor = declaration.walk();
    let mut errors = declaration
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "ERROR");
    let Some(error) = errors.next() else {
        return false;
    };
    errors.next().is_none()
        && error.named_child_count() == 1
        && error.named_child(0).is_some_and(|class| {
            class.kind() == "identifier" && node_text(class, source) == "class"
        })
}

pub fn is_ordinary_macro_reference_node(node: Node<'_>) -> bool {
    if !matches!(node.kind(), "identifier" | "field_identifier") || is_declaration_name(node) {
        return false;
    }
    if let Some(parent) = node.parent() {
        if parent.kind() == "call_expression"
            && parent.child_by_field_name("function") == Some(node)
        {
            return false;
        }
        if matches!(parent.kind(), "labeled_statement" | "goto_statement")
            && parent.child_by_field_name("label") == Some(node)
        {
            return false;
        }
    }
    let mut current = node.parent();
    while let Some(ancestor) = current {
        match ancestor.kind() {
            "preproc_ifdef" | "preproc_ifndef" => {
                if ancestor
                    .child_by_field_name("name")
                    .is_some_and(|name| node_range_contains(name, node))
                {
                    return false;
                }
            }
            "preproc_if" | "preproc_elif" => {
                if ancestor
                    .child_by_field_name("condition")
                    .is_some_and(|condition| node_range_contains(condition, node))
                {
                    return false;
                }
            }
            "preproc_else" => {}
            kind if kind.starts_with("preproc_") => return false,
            _ => {}
        }
        if matches!(
            ancestor.kind(),
            "translation_unit" | "function_definition" | "compound_statement"
        ) {
            break;
        }
        current = ancestor.parent();
    }
    true
}

fn node_range_contains(outer: Node<'_>, inner: Node<'_>) -> bool {
    outer.start_byte() <= inner.start_byte() && inner.end_byte() <= outer.end_byte()
}

fn recovered_c_reference_node(
    visibility: &VisibilityIndex<'_>,
    file: &ProjectFile,
    node: Node<'_>,
    source: &str,
) -> bool {
    if node.start_byte() >= node.end_byte()
        || node.is_error()
        || node.is_missing()
        || !matches!(
            node.kind(),
            "identifier" | "field_identifier" | "type_identifier" | "namespace_identifier"
        )
        || recovered_c_macro_binding_role(node)
        || recovered_c_label_role(node)
    {
        return false;
    }

    let name = node_text(node, source);
    if !name.is_empty() && visibility.macro_name_may_be_bound_at(file, name, node.start_byte()) {
        return true;
    }
    if recovered_c_explicit_assignment_callee(visibility, file, node, name) {
        return true;
    }
    if is_declaration_name(node) {
        return false;
    }
    if matches!(node.kind(), "type_identifier" | "namespace_identifier") {
        return true;
    }
    recovered_c_reference_anchor(node)
}

fn recovered_c_explicit_assignment_callee(
    visibility: &VisibilityIndex<'_>,
    file: &ProjectFile,
    node: Node<'_>,
    name: &str,
) -> bool {
    let mut current = node;
    let error = loop {
        let Some(parent) = current.parent() else {
            return false;
        };
        if parent.is_error() {
            break parent;
        }
        current = parent;
    };
    let mut cursor = error.walk();
    let explicit_recovery_precedes_callee = error
        .named_children(&mut cursor)
        .take_while(|child| child.start_byte() < node.start_byte())
        .any(|child| child.kind() == "explicit_function_specifier");
    if !explicit_recovery_precedes_callee {
        return false;
    }
    visibility
        .cpp
        .declarations(file)
        .iter()
        .chain(visibility.visible_by_file.get(file).into_iter().flatten())
        .any(|candidate| candidate.identifier() == name && candidate.is_function())
}

fn recovered_c_macro_binding_role(mut node: Node<'_>) -> bool {
    while let Some(parent) = node.parent() {
        if matches!(
            parent.kind(),
            "preproc_def" | "preproc_function_def" | "preproc_params"
        ) {
            return true;
        }
        if parent.is_error()
            || matches!(
                parent.kind(),
                "translation_unit" | "function_definition" | "compound_statement"
            )
        {
            return false;
        }
        node = parent;
    }
    false
}

fn recovered_c_label_role(node: Node<'_>) -> bool {
    node.parent().is_some_and(|parent| {
        matches!(parent.kind(), "labeled_statement" | "goto_statement")
            && parent.child_by_field_name("label") == Some(node)
    })
}

fn recovered_c_reference_anchor(mut node: Node<'_>) -> bool {
    while let Some(parent) = node.parent() {
        if parent.is_error() {
            return false;
        }
        if parent.kind().ends_with("_expression")
            || matches!(
                parent.kind(),
                "argument_list"
                    | "return_statement"
                    | "expression_statement"
                    | "case_statement"
                    | "initializer_list"
                    | "init_declarator"
                    | "array_declarator"
                    | "field_designator"
                    | "enumerator"
            )
        {
            return true;
        }
        if matches!(
            parent.kind(),
            "translation_unit"
                | "function_definition"
                | "compound_statement"
                | "declaration"
                | "field_declaration"
                | "parameter_declaration"
        ) {
            return false;
        }
        node = parent;
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

pub fn is_parameter_type_reference(node: Node<'_>) -> bool {
    let mut current = node.parent();
    while let Some(ancestor) = current {
        if matches!(
            ancestor.kind(),
            "parameter_declaration" | "optional_parameter_declaration"
        ) {
            return ancestor
                .child_by_field_name("type")
                .is_some_and(|type_node| {
                    type_node.start_byte() <= node.start_byte()
                        && node.end_byte() <= type_node.end_byte()
                });
        }
        if matches!(
            ancestor.kind(),
            "function_definition" | "lambda_expression" | "compound_statement"
        ) {
            return false;
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
        "reference_declarator" | "parenthesized_declarator" => {
            node.named_child(0).and_then(declarator_name_node)
        }
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

/// True when each structured qualifier on the callable-name path has a real
/// `::` token. A macro-prefixed return type can make tree-sitter insert a
/// zero-width missing separator and parse `TYPE Result<T> method()` as the
/// false qualified declarator `Result<T>::method`.
pub fn qualified_name_has_concrete_scope_separators(node: Node<'_>) -> bool {
    let mut stack = vec![node];
    let mut found_separator = false;
    while let Some(current) = stack.pop() {
        if !matches!(
            current.kind(),
            "qualified_identifier" | "scoped_identifier" | "scoped_type_identifier"
        ) {
            continue;
        }
        let mut current_has_separator = false;
        for index in 0..current.child_count() {
            let Some(child) = current.child(index) else {
                continue;
            };
            if child.kind() == "::" {
                if child.is_missing() {
                    return false;
                }
                current_has_separator = true;
                found_separator = true;
            }
        }
        if !current_has_separator {
            return false;
        }
        for field in ["scope", "name"] {
            if let Some(child) = current.child_by_field_name(field)
                && matches!(
                    child.kind(),
                    "qualified_identifier" | "scoped_identifier" | "scoped_type_identifier"
                )
            {
                stack.push(child);
            }
        }
    }
    found_separator
}

pub fn qualified_owner_components<'tree>(
    node: Node<'tree>,
    source: &str,
) -> Option<QualifiedOwnerComponents<'tree>> {
    if !qualified_name_has_concrete_scope_separators(node) {
        return None;
    }
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
                qualified.names.len(),
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

/// Resolve a structured type spelling from an object-like macro replacement
/// when definition-site source order has no answer.
///
/// Macro replacement tokens are looked up where the macro is expanded, so a
/// type declared later in the defining header can still be their destination.
/// Without expanding every invocation, accept only one include-visible logical
/// class or alias whose structured path ends in the replacement components.
/// An ordinary lexical answer always takes precedence at the call site.
pub fn unique_macro_replacement_type_candidate(
    analyzer: &CppGraphSource<'_>,
    visibility: &VisibilityIndex<'_>,
    file: &ProjectFile,
    components: &[String],
) -> Option<CodeUnit> {
    let terminal = components.last()?;
    let mut candidates = Vec::new();
    for candidate in visibility
        .visible_identifier_candidates(file, terminal)
        .filter(|candidate| candidate.is_class() || declared_type_alias(analyzer, candidate))
        .filter(|candidate| canonical_cpp_scope_components(candidate).ends_with(components))
    {
        if !candidates
            .iter()
            .any(|existing| same_logical_symbol(existing, candidate))
        {
            candidates.push(candidate.clone());
        }
    }
    (candidates.len() == 1).then(|| candidates.remove(0))
}

/// The base scopes named by member using-declarations for `member` in one
/// class source range.
///
/// The grammar supplies the qualified identifier and each component. Keep
/// this interpretation shared between forward overload lookup and inverse
/// owner routing rather than reparsing a rendered `Base::member` string at
/// either call site.
pub fn cpp_member_using_declaration_scopes(source: &str, member: &str) -> Vec<String> {
    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_cpp::LANGUAGE.into())
        .is_err()
    {
        return Vec::new();
    }
    let Some(tree) = parser.parse(source, None) else {
        return Vec::new();
    };
    let mut scopes = Vec::new();
    let mut pending = vec![tree.root_node()];
    while let Some(node) = pending.pop() {
        if node.kind() == "using_declaration" {
            let Some(imported) = node.named_child(0) else {
                continue;
            };
            let Some(mut components) = cpp_type_name_components(imported, source) else {
                continue;
            };
            if components.pop().as_deref() == Some(member) && !components.is_empty() {
                scopes.push(components.join("::"));
            }
            continue;
        }
        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(index) {
                pending.push(child);
            }
        }
    }
    scopes
}

/// Whether a structured using-declaration scope can name `qualified` as an
/// ancestor class. The boundary check prevents `Base` from matching
/// `OtherBase` while allowing a relative `Base` spelling to match `ns::Base`.
pub fn cpp_qualified_name_has_scope_suffix(qualified: &str, scope: &str) -> bool {
    qualified == scope
        || qualified
            .strip_suffix(scope)
            .is_some_and(|prefix| prefix.ends_with("::"))
}

/// Whether `node` is the direct structured type payload of a template
/// argument. This role remains meaningful even when a surrounding expression
/// is below tree-sitter recovery, because both the `template_argument_list`
/// and the `type_descriptor` retain their named fields.
pub fn is_cpp_template_argument_type_leaf(node: Node<'_>) -> bool {
    let Some(type_descriptor) = node.parent() else {
        return false;
    };
    if type_descriptor.kind() != "type_descriptor"
        || type_descriptor.child_by_field_name("type") != Some(node)
    {
        return false;
    }
    let Some(arguments) = type_descriptor.parent() else {
        return false;
    };
    if arguments.kind() != "template_argument_list" {
        return false;
    }
    arguments.parent().is_some_and(|parent| {
        matches!(parent.kind(), "template_type" | "template_function")
            && parent.child_by_field_name("arguments") == Some(arguments)
    })
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
                            // One template term from a resolver query; see `ParentIndex::unindexed`.
                            term: cpp_template_term(
                                argument,
                                source,
                                &[],
                                &ParentIndex::unindexed(),
                            ),
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
            "dependent_name" => stack.push(current.named_child(0)?),
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
/// definitions from the ancestor chain. Preserve the order of every namespace
/// that did survive parsing, but allow indexed components between them. An
/// empty path is accepted only when the declarator itself supplies a nested
/// owner suffix such as `Outer::Inner`: together with the indexed enclosing
/// owner chain, that suffix is structural evidence that a namespace was lost.
/// A one-segment owner at the translation-unit root remains insufficient.
fn indexed_namespace_path_is_recoverable(
    lexical_scope: &[String],
    indexed_owner_scope: &[String],
    explicit_owner_component_count: usize,
) -> bool {
    if lexical_scope.is_empty() {
        return explicit_owner_component_count > 1;
    }
    if lexical_scope.len() >= indexed_owner_scope.len() {
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

/// Whether a declaration type is initialized with a pointer cast.
///
/// This structured shape has an independent qualified occurrence in addition
/// to the cast descriptor below it. Other declarations must keep their normal
/// full-range occurrence only.
pub(crate) fn initialized_type_declaration_with_cast(node: Node<'_>) -> bool {
    let mut current = Some(node);
    while let Some(candidate) = current {
        if candidate.kind() == "declaration" {
            let Some(type_node) = candidate.child_by_field_name("type") else {
                return false;
            };
            if !(type_node.start_byte() <= node.start_byte()
                && node.end_byte() <= type_node.end_byte())
            {
                return false;
            }
            let mut cursor = candidate.walk();
            return candidate.named_children(&mut cursor).any(|child| {
                child.kind() == "init_declarator"
                    && child
                        .child_by_field_name("value")
                        .is_some_and(|value| value.kind() == "cast_expression")
            });
        }
        current = candidate.parent();
    }
    false
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum QualifiedAliasReferenceKind {
    Ordinary,
    ConstructorWithExpressionArgument,
    ExhaustiveTemplate,
}

/// Whether a qualified alias reference preserves the requested target.
///
/// The complete qualified spelling and its terminal identifier are both valid
/// occurrences when the visible alias path is structurally proven to name the
/// target. Template aliases use their bound arguments; ordinary aliases use
/// their structured primary chain.
pub(crate) fn qualified_alias_reference_preserves_target(
    node: Node<'_>,
    target: &CodeUnit,
    analyzer: &CppGraphSource<'_>,
    visibility: &VisibilityIndex<'_>,
    file: &ProjectFile,
    source: &str,
) -> Option<QualifiedAliasReferenceKind> {
    if !matches!(
        node.kind(),
        "qualified_identifier" | "scoped_identifier" | "scoped_type_identifier"
    ) {
        return None;
    }
    let components = cpp_type_name_components(node, source)?;
    let name = components.last()?;
    analyzer.type_alias_provider().and_then(|provider| {
        visibility
            .visible_identifier_candidates(file, name)
            .find_map(|candidate| {
                let proof = provider.is_type_alias(candidate)
                    && canonical_cpp_scope_components(candidate) == components
                    && visibility.external_type_candidate_visible_in_context(
                        analyzer, file, candidate, node,
                    )
                    && match cpp_template_reference_arguments(node, source) {
                        Some(arguments) => visibility.template_alias_arguments_preserve_target(
                            analyzer, file, candidate, &arguments, target,
                        ),
                        None => visibility.structured_alias_primary_preserves_target(
                            analyzer, file, candidate, target,
                        ),
                    };
                proof.then(|| {
                    if cpp_template_reference_arguments(node, source).is_some()
                        && visibility.is_exhaustive_same_fqn_type_declaration_family(
                            analyzer, file, candidate,
                        )
                    {
                        QualifiedAliasReferenceKind::ExhaustiveTemplate
                    } else if qualified_alias_constructor_has_expression_argument(node)
                        || qualified_alias_local_constructor_declaration(node)
                    {
                        QualifiedAliasReferenceKind::ConstructorWithExpressionArgument
                    } else {
                        QualifiedAliasReferenceKind::Ordinary
                    }
                })
            })
    })
}

pub(crate) fn qualified_alias_reference_requires_terminal(
    reference: Option<QualifiedAliasReferenceKind>,
) -> bool {
    matches!(
        reference,
        Some(
            QualifiedAliasReferenceKind::ConstructorWithExpressionArgument
                | QualifiedAliasReferenceKind::ExhaustiveTemplate
        )
    )
}

fn qualified_alias_constructor_has_expression_argument(node: Node<'_>) -> bool {
    let Some(declaration) = node.parent().filter(|parent| {
        parent.kind() == "declaration" && parent.child_by_field_name("type") == Some(node)
    }) else {
        return false;
    };
    let mut cursor = declaration.walk();
    declaration.named_children(&mut cursor).any(|child| {
        child.kind() == "init_declarator"
            && child
                .child_by_field_name("value")
                .filter(|value| value.kind() == "argument_list")
                .is_some_and(|arguments| {
                    let mut cursor = arguments.walk();
                    arguments.named_children(&mut cursor).any(|argument| {
                        let is_parameter = matches!(
                            argument.kind(),
                            "parameter_declaration" | "optional_parameter_declaration"
                        );
                        if is_parameter {
                            argument
                                .child_by_field_name("type")
                                .is_some_and(|type_node| {
                                    type_node.kind() == "type_identifier"
                                        && argument.child_by_field_name("declarator").is_none()
                                })
                        } else {
                            !argument.kind().ends_with("_literal")
                                && !matches!(argument.kind(), "true" | "false" | "nullptr")
                        }
                    })
                })
    })
}

/// Tree-sitter represents a local C++ direct construction such as
/// `Alias value(argument)` as a function declarator. Restrict that recovery to
/// declarations inside a compound statement so namespace-scope function
/// declarations with the same qualified return type stay full-range only.
fn qualified_alias_local_constructor_declaration(node: Node<'_>) -> bool {
    let Some(declaration) = node.parent().filter(|parent| {
        parent.kind() == "declaration" && parent.child_by_field_name("type") == Some(node)
    }) else {
        return false;
    };
    if declaration
        .parent()
        .is_none_or(|parent| parent.kind() != "compound_statement")
    {
        return false;
    }
    let mut cursor = declaration.walk();
    declaration
        .named_children(&mut cursor)
        .any(|child| child.kind() == "function_declarator")
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
            | "template_method"
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

#[derive(Clone, Copy)]
pub struct RecoveredRelationalTemplateMemberCall<'tree> {
    pub receiver: Node<'tree>,
    pub member: Node<'tree>,
    pub arity: usize,
}

/// Recover `receiver.member<argument>(call_arguments)` when tree-sitter chose
/// nested relational expressions instead of a `template_method` call.
///
/// The recovery uses only grammar fields: the selected field must be the left
/// side of `<`, that expression must be the left side of `>`, and the right
/// side of `>` must be the parenthesized call arguments. Semantic callers must
/// additionally prove the receiver owner and the member's template status.
pub fn recovered_relational_template_member_call(
    field: Node<'_>,
) -> Option<RecoveredRelationalTemplateMemberCall<'_>> {
    if field.kind() != "field_expression" {
        return None;
    }
    let receiver = field
        .child_by_field_name("argument")
        .or_else(|| field.child_by_field_name("object"))?;
    let member = field.child_by_field_name("field")?;
    let less = field.parent()?;
    if less.kind() != "binary_expression"
        || less.child_by_field_name("left") != Some(field)
        || less
            .child_by_field_name("operator")
            .is_none_or(|operator| operator.kind() != "<")
        || less.child_by_field_name("right").is_none()
    {
        return None;
    }
    let greater = less.parent()?;
    if greater.kind() != "binary_expression"
        || greater.child_by_field_name("left") != Some(less)
        || greater
            .child_by_field_name("operator")
            .is_none_or(|operator| operator.kind() != ">")
    {
        return None;
    }
    let arguments = greater.child_by_field_name("right")?;
    if arguments.kind() != "parenthesized_expression" {
        return None;
    }
    let arity = parenthesized_call_argument_arity(arguments)?;
    Some(RecoveredRelationalTemplateMemberCall {
        receiver,
        member,
        arity,
    })
}

fn parenthesized_call_argument_arity(arguments: Node<'_>) -> Option<usize> {
    let expression = arguments.named_child(0)?;
    if expression.kind() != "comma_expression" {
        return Some(1);
    }
    let mut arity = 0usize;
    let mut stack = vec![expression];
    while let Some(node) = stack.pop() {
        if node.kind() == "comma_expression" {
            stack.push(node.child_by_field_name("right")?);
            stack.push(node.child_by_field_name("left")?);
        } else {
            arity += 1;
        }
    }
    Some(arity)
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

pub fn type_reference_hit_node(node: Node<'_>) -> Node<'_> {
    if is_call_callee_node(node) {
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
        TargetKind::Macro => unit.is_macro(),
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

fn target_type_owner_resolution(
    analyzer: &CppGraphSource<'_>,
    code_unit: &CodeUnit,
) -> Option<ResolvedTypeOwner> {
    match type_owner_resolution(analyzer, code_unit) {
        Some(owner) if owner.unit.is_class() && !owner.is_forward_declaration => Some(owner),
        Some(_) | None => target_forward_owner_resolution(analyzer, code_unit),
    }
}

/// Recover method identity for an indexed out-of-line definition when the
/// ordinary parent edge is absent. Prefer the unique include-visible forward
/// declaration, then classify exact-FQN class declarations elsewhere in the
/// workspace. A unique complete declaration wins; otherwise multiple forward
/// declarations are one owner only when they all share one logical identity.
/// The qualified callable FQN proves that owner spelling even when its defining
/// header is outside the scan file's include closure, while unknown or competing
/// complete declarations remain ambiguous.
/// This is deliberately target-only: canonical declaration resolution must
/// continue to prefer the callable definition rather than replacing it with
/// the recovered owner.
fn target_forward_owner_resolution(
    analyzer: &CppGraphSource<'_>,
    code_unit: &CodeUnit,
) -> Option<ResolvedTypeOwner> {
    if !code_unit.is_function() {
        return None;
    }
    // A top-level free function has no owner at all, and `FqName::parent`
    // answers the empty name rather than `None` for a one-segment identity.
    // `default_parent_fq_name`, which this replaced, filtered that case out;
    // asking the relational store for the empty name is a batch error that
    // fails the whole target frontier.
    let owner_name = code_unit.fq().parent().filter(|owner| !owner.is_empty())?;
    let cpp = analyzer.cpp?;
    let mut visible_files = HashSet::default();
    collect_include_closure(
        analyzer,
        cpp.include_target_index(),
        code_unit.source(),
        &mut visible_files,
        None,
    );
    let candidates = analyzer.workspace_definitions().exact(&owner_name);
    let visible_candidates = candidates
        .iter()
        .filter(|candidate| candidate.is_class() && visible_files.contains(candidate.source()))
        .cloned()
        .collect::<Vec<_>>();
    match classify_direct_owner_candidates(analyzer, visible_candidates.into_iter()) {
        DirectOwnerResolution::UniqueFull(unit) => {
            return Some(ResolvedTypeOwner {
                unit,
                is_forward_declaration: false,
            });
        }
        DirectOwnerResolution::ForwardsOnly(forwards) => {
            return (forwards.len() == 1).then(|| ResolvedTypeOwner {
                unit: forwards.into_iter().next().unwrap(),
                is_forward_declaration: true,
            });
        }
        DirectOwnerResolution::Ambiguous => return None,
        DirectOwnerResolution::None => {}
    }

    let candidates = candidates
        .into_iter()
        .filter(|candidate| candidate.is_class())
        .collect::<Vec<_>>();
    let (unit, is_forward_declaration) =
        match classify_direct_owner_candidates(analyzer, candidates.iter().cloned()) {
            DirectOwnerResolution::UniqueFull(unit) => (unit, false),
            DirectOwnerResolution::ForwardsOnly(forwards) => {
                (unique_logical_forward_owner(forwards)?, true)
            }
            DirectOwnerResolution::None | DirectOwnerResolution::Ambiguous => return None,
        };
    Some(ResolvedTypeOwner {
        unit,
        is_forward_declaration,
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
    if !code_unit.owner_is_type_scope() {
        return fallback.map(|unit| ResolvedTypeOwner {
            unit,
            is_forward_declaration: false,
        });
    }
    let owner_fq = code_unit
        .fq()
        .parent()
        .expect("a unit with an owner identifier has a structured parent");
    let owner_candidates = analyzer.workspace_definitions().exact(&owner_fq);
    match same_source_owner(analyzer, code_unit, &owner_candidates) {
        DirectOwnerResolution::UniqueFull(owner) => {
            return Some(ResolvedTypeOwner {
                unit: owner,
                is_forward_declaration: false,
            });
        }
        DirectOwnerResolution::Ambiguous => return None,
        DirectOwnerResolution::ForwardsOnly(_) | DirectOwnerResolution::None => {}
    }
    match directly_included_owner(analyzer, code_unit, &owner_candidates) {
        DirectOwnerResolution::UniqueFull(owner) => Some(ResolvedTypeOwner {
            unit: owner,
            is_forward_declaration: false,
        }),
        DirectOwnerResolution::Ambiguous => None,
        DirectOwnerResolution::ForwardsOnly(forwards) => {
            match visible_full_cpp_owner(analyzer, code_unit, &owner_candidates) {
                FullOwnerResolution::Unique(owner) => Some(ResolvedTypeOwner {
                    unit: owner,
                    is_forward_declaration: false,
                }),
                FullOwnerResolution::None => {
                    unique_logical_forward_owner(forwards).map(|unit| ResolvedTypeOwner {
                        unit,
                        is_forward_declaration: true,
                    })
                }
                FullOwnerResolution::Ambiguous => None,
            }
        }
        DirectOwnerResolution::None => {
            match visible_full_cpp_owner(analyzer, code_unit, &owner_candidates) {
                FullOwnerResolution::Unique(owner) => Some(ResolvedTypeOwner {
                    unit: owner,
                    is_forward_declaration: false,
                }),
                FullOwnerResolution::Ambiguous => None,
                FullOwnerResolution::None => fallback
                    .filter(|parent| {
                        parent.source() == code_unit.source()
                            && parent.fq() == &owner_fq
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
    owner_candidates: &[CodeUnit],
) -> DirectOwnerResolution {
    let candidates = owner_candidates
        .iter()
        .filter(|candidate| candidate.is_class() && candidate.source() == code_unit.source())
        .cloned()
        .collect::<Vec<_>>();
    let candidates = prefer_member_declaring_owners(analyzer, code_unit, candidates);
    classify_direct_owner_candidates(analyzer, candidates.into_iter())
}

fn visible_full_cpp_owner(
    analyzer: &CppGraphSource<'_>,
    code_unit: &CodeUnit,
    owner_candidates: &[CodeUnit],
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
    let candidates = owner_candidates
        .iter()
        .filter(|candidate| candidate.is_class() && visible_files.contains(candidate.source()))
        .cloned()
        .collect::<Vec<_>>();
    let candidates = prefer_member_declaring_owners(analyzer, code_unit, candidates);
    let mut full_definition = None;
    for candidate in candidates {
        match cpp_class_declaration_strength(analyzer, &candidate) {
            CppClassDeclarationStrength::Full if full_definition.is_some() => {
                return FullOwnerResolution::Ambiguous;
            }
            CppClassDeclarationStrength::Full => full_definition = Some(candidate),
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
    owner_candidates: &[CodeUnit],
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
    let candidates = owner_candidates
        .iter()
        .filter(|candidate| candidate.is_class() && direct_includes.contains(candidate.source()))
        .cloned()
        .collect::<Vec<_>>();
    let candidates = prefer_member_declaring_owners(analyzer, code_unit, candidates);
    classify_direct_owner_candidates(analyzer, candidates.into_iter())
}

fn prefer_member_declaring_owners(
    analyzer: &CppGraphSource<'_>,
    member: &CodeUnit,
    candidates: Vec<CodeUnit>,
) -> Vec<CodeUnit> {
    let matching = candidates
        .iter()
        .filter(|owner| owner_declares_member(analyzer, owner, member))
        .cloned()
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

fn classify_direct_owner_candidates(
    analyzer: &CppGraphSource<'_>,
    candidates: impl Iterator<Item = CodeUnit>,
) -> DirectOwnerResolution {
    collapse_owner_candidates(candidates.map(|candidate| {
        let strength = cpp_class_declaration_strength(analyzer, &candidate);
        (candidate, strength)
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

#[cfg(any(test, feature = "test-support"))]
pub fn unique_logical_forward_owner_for_test(forwards: Vec<CodeUnit>) -> Option<CodeUnit> {
    unique_logical_forward_owner(forwards)
}

fn unique_logical_forward_owner(mut forwards: Vec<CodeUnit>) -> Option<CodeUnit> {
    let first = forwards.pop()?;
    forwards
        .iter()
        .all(|forward| same_logical_symbol(forward, &first))
        .then_some(first)
}

pub fn cpp_class_declaration_strength(
    analyzer: &CppGraphSource<'_>,
    candidate: &CodeUnit,
) -> CppClassDeclarationStrength {
    // The answer is a pure function of the unit's ranges and its file's tree,
    // and the inverse scan asks it once per declaration seed. On a translation
    // unit the parser could not fully recover, each ask re-derives the
    // export-macro recovery shapes from the file's `ERROR` subtrees, so without
    // this memo one file's scan is quadratic in its own size: 97% of Catch2's
    // 284 s inverse scan of `extras/catch_amalgamated.cpp` was in this call
    // (#1496).
    let Some(cpp) = analyzer.cpp else {
        return uncached_cpp_class_declaration_strength(analyzer, candidate);
    };
    if let Some(strength) = cpp.cached_class_declaration_strength(candidate) {
        return strength;
    }
    let strength = uncached_cpp_class_declaration_strength(analyzer, candidate);
    cpp.cache_class_declaration_strength(candidate, strength);
    strength
}

fn uncached_cpp_class_declaration_strength(
    analyzer: &CppGraphSource<'_>,
    candidate: &CodeUnit,
) -> CppClassDeclarationStrength {
    if let Some(cpp) = analyzer.cpp
        && let Some(prepared) = cpp.prepared_syntax(analyzer.token, candidate.source())
    {
        return cpp_class_declaration_strength_in_tree(
            analyzer,
            &cpp.recovered_export_class_index(analyzer.token, candidate.source()),
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
    // This branch reparses a file the analyzer has no prepared tree for, so its
    // recovery index is that one tree's and cannot be shared.
    let recovered_export_classes =
        CppRecoveredExportClassIndex::build(tree.root_node(), source.as_str());
    cpp_class_declaration_strength_in_tree(
        analyzer,
        &recovered_export_classes,
        candidate,
        &source,
        tree.root_node(),
    )
}

fn cpp_class_declaration_strength_in_tree(
    analyzer: &CppGraphSource<'_>,
    recovered_export_classes: &CppRecoveredExportClassIndex,
    candidate: &CodeUnit,
    source: &str,
    root: Node<'_>,
) -> CppClassDeclarationStrength {
    let ranges = analyzer.ranges(candidate);
    let mut saw_forward = false;
    for range in ranges {
        // The recovered export-macro shapes answer for their own ranges; only a
        // range no recovery claims is read as a plain specifier.
        match recovered_class_body_at(
            recovered_export_classes,
            root,
            source,
            candidate.identifier(),
            &range,
        ) {
            Some(true) => return CppClassDeclarationStrength::Full,
            Some(false) => {
                saw_forward = true;
                continue;
            }
            None => {}
        }
        // Only a node covering the range's start byte can be the specifier for
        // this range, so apply that test where nodes enter the stack rather
        // than where they leave it. Pushing first meant one ask enqueued every
        // sibling at every level it descended, which on a translation unit with
        // thousands of top-level declarations is a per-ask cost proportional to
        // the file (#1496).
        let covers_range_start = |node: &Node<'_>| {
            node.start_byte() <= range.start_byte && node.end_byte() >= range.start_byte
        };
        let mut stack = Vec::new();
        if covers_range_start(&root) {
            stack.push(root);
        }
        while let Some(node) = stack.pop() {
            if node.start_byte() == range.start_byte
                && node.end_byte() == range.end_byte
                && matches!(
                    node.kind(),
                    "class_specifier" | "struct_specifier" | "union_specifier" | "enum_specifier"
                )
            {
                if cpp_class_node_has_body(node) {
                    return CppClassDeclarationStrength::Full;
                }
                saw_forward = true;
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor).filter(covers_range_start));
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
    if !code_unit.owner_is_type_scope() {
        return None;
    }
    let owner_fq = code_unit.fq().parent()?;
    ctx.analyzer
        .workspace_definitions()
        .exact(&owner_fq)
        .into_iter()
        .find(|candidate| candidate.is_class() && ctx.visibility.is_visible(ctx.file, candidate))
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
                .filter_map(|peer| cpp_global_field_declaration_linkage(analyzer, &peer))
                .any(|linkage| matches!(linkage, CppFieldLinkage::External))
        }
    }
}

fn cpp_global_field_linkage_peers<'a>(
    analyzer: &CppGraphSource<'a>,
    candidate: &'a CodeUnit,
) -> impl Iterator<Item = CodeUnit> + 'a {
    let name = candidate.fq().clone();
    analyzer
        .workspace_definitions()
        .exact(&name)
        .into_iter()
        .filter(move |peer| {
            if peer == candidate {
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
    if let Some(prepared) = cpp.prepared_syntax(analyzer.token, candidate.source()) {
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
            .map(|declaration| {
                // One question about one declaration; see `ParentIndex::unindexed`.
                cpp_field_declaration_linkage(declaration, source, &ParentIndex::unindexed())
            })
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

    #[test]
    fn c_sizeof_expression_type_candidate_is_structural_and_c_only() {
        let source = "int size(void) { return sizeof(((Payload))); }\n";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .expect("C++ grammar");
        let tree = parser.parse(source, None).expect("fixture tree");
        let start = source.find("Payload").expect("sizeof operand");
        let node = tree
            .root_node()
            .named_descendant_for_byte_range(start, start + "Payload".len())
            .expect("focused operand");
        let c_file = ProjectFile::new(std::env::temp_dir(), "issue.c");
        let cpp_file = ProjectFile::new(std::env::temp_dir(), "issue.cpp");

        assert_eq!(node.kind(), "identifier");
        assert!(is_c_sizeof_expression_type_candidate(&c_file, node));
        assert!(!is_c_sizeof_expression_type_candidate(&cpp_file, node));
    }

    fn parse_cpp(source: &str) -> Tree {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .expect("C++ grammar");
        parser.parse(source, None).expect("fixture tree")
    }

    fn named_node_at<'tree>(tree: &'tree Tree, source: &str, needle: &str) -> Node<'tree> {
        let start = source.find(needle).expect("fixture needle");
        tree.root_node()
            .named_descendant_for_byte_range(start, start + needle.len())
            .expect("node at needle")
    }

    /// Two macro-decorated class heads make tree-sitter close `detail` at the
    /// first class's `}`, `matchers` at the second's, and `app` at `detail`'s
    /// real `}`; the tail parses at translation-unit level and the two real
    /// closes for `matchers` and `app` land in a trailing ERROR (#1537).
    const STOLEN_BRACE_CASCADE: &str = r#"namespace app {
namespace matchers {
    namespace detail {
        class API [[nodiscard]] First {
        public:
            int value() const { return count_ + 1; }
        private:
            int count_;
        };
        class API [[nodiscard]] Second {
        public:
            int value() const { return count_ + 2; }
        private:
            int count_;
        };
    } // namespace detail

    template <typename T>
    void tail_function(MatcherBase<T> const& value);

    class TailClass {};
} // namespace matchers
} // namespace app

struct AfterAll {};
"#;

    #[test]
    fn orphaned_namespace_scope_index_restores_a_stolen_brace_cascade() {
        let source = STOLEN_BRACE_CASCADE;
        let tree = parse_cpp(source);
        let index = OrphanedNamespaceScopeIndex::build(tree.root_node(), source);

        let tail_class = named_node_at(&tree, source, "TailClass");
        assert!(
            !has_ancestor_kind(tail_class, "namespace_definition"),
            "the fixture must reproduce the recovery: the tail has no namespace ancestor"
        );
        let displaced = named_node_at(&tree, source, "Second");
        assert_eq!(
            enclosing_namespace_components(displaced, source),
            Some(vec!["app".to_string(), "matchers".to_string()]),
            "the fixture must displace the second class out of detail"
        );

        let components = |needle: &str| {
            index.enclosing_namespace_components(named_node_at(&tree, source, needle), source)
        };
        assert_eq!(components("First"), ["app", "matchers", "detail"]);
        assert_eq!(components("Second"), ["app", "matchers", "detail"]);
        assert_eq!(components("MatcherBase<T>"), ["app", "matchers"]);
        assert_eq!(components("tail_function"), ["app", "matchers"]);
        assert_eq!(components("TailClass"), ["app", "matchers"]);
        assert!(components("AfterAll").is_empty());
    }

    #[test]
    fn orphaned_namespace_scope_index_is_empty_without_lost_scopes() {
        let clean = "namespace a { namespace b { class C {}; } class D {}; }\n";
        let tree = parse_cpp(clean);
        assert!(!tree.root_node().has_error());
        assert!(OrphanedNamespaceScopeIndex::build(tree.root_node(), clean).is_empty());

        // A namespace that merely contains a parse error closes where its
        // brace says; the declarations after it keep their parsed scope.
        let damaged = "namespace a { namespace b { UNKNOWN_MACRO(x) } class C {}; }\n";
        let tree = parse_cpp(damaged);
        assert!(tree.root_node().has_error());
        let index = OrphanedNamespaceScopeIndex::build(tree.root_node(), damaged);
        assert_eq!(
            index.enclosing_namespace_components(named_node_at(&tree, damaged, "class C"), damaged),
            ["a"]
        );
    }

    #[test]
    fn empty_parser_namespace_requires_a_nested_indexed_owner_suffix() {
        let indexed = ["cache", "Outer", "Inner"].map(str::to_string);
        assert!(indexed_namespace_path_is_recoverable(&[], &indexed, 2));
        assert!(!indexed_namespace_path_is_recoverable(&[], &indexed, 1));
        assert!(indexed_namespace_path_is_recoverable(
            &["cache".to_string()],
            &indexed,
            1,
        ));
    }

    #[test]
    fn sort_lookup_units_totally_orders_every_identity_field() {
        let file = ProjectFile::new(std::env::temp_dir(), "issue_1876.cpp");
        let base = CodeUnit::with_signature(
            file.clone(),
            CodeUnitType::Function,
            "scope",
            "value",
            Some("()".to_string()),
            false,
        );
        let different_kind = CodeUnit::with_signature(
            file.clone(),
            CodeUnitType::Field,
            "scope",
            "value",
            Some("()".to_string()),
            false,
        );
        let synthetic = base.with_synthetic(true);

        let interner = segment_interner();
        let mut member_fq = FqName::new();
        member_fq.push(interner.intern("scope", SegmentKind::Package));
        member_fq.push(interner.intern("value", SegmentKind::Member));
        let different_package_boundary = CodeUnit::from_fq(
            file.clone(),
            CodeUnitType::Function,
            member_fq,
            0,
            Some("()".to_string()),
            false,
        );

        let mut unknown_fq = FqName::new();
        unknown_fq.push(interner.intern("scope", SegmentKind::Package));
        unknown_fq.push(interner.intern("value", SegmentKind::Unknown));
        let different_segment_kind = CodeUnit::from_fq(
            file,
            CodeUnitType::Function,
            unknown_fq,
            1,
            Some("()".to_string()),
            false,
        );

        let input = vec![
            base,
            different_kind,
            synthetic,
            different_package_boundary,
            different_segment_kind,
        ];
        let mut expected = input.clone();
        sort_lookup_units(&mut expected);
        assert!(expected.windows(2).all(|pair| {
            let mut ordered = pair.to_vec();
            sort_lookup_units(&mut ordered);
            ordered == pair && pair[0] != pair[1]
        }));

        let mut reversed = input.clone();
        reversed.reverse();
        sort_lookup_units(&mut reversed);
        assert_eq!(reversed, expected);

        let mut rotated = input;
        rotated.rotate_left(2);
        sort_lookup_units(&mut rotated);
        assert_eq!(rotated, expected);
    }

    #[test]
    fn displaced_preprocessor_terminator_bounds_the_real_guard() {
        let damaged = "#ifndef API_H\n#define API_H\nextern char option_buffer[\n#ifdef FEATURE_X\n    16 +\n#endif\n    1];\n\nvoid target(void);\n#endif\n";
        let guarded = "#ifdef FEATURE_X\nvoid target(void);\n#endif\n";
        let parse = |source: &str| {
            let mut parser = Parser::new();
            parser
                .set_language(&tree_sitter_cpp::LANGUAGE.into())
                .expect("C++ grammar");
            parser.parse(source, None).expect("fixture tree")
        };

        let tree = parse(damaged);
        let root = tree.root_node();
        let target = damaged.find("target").expect("target byte");
        let declaration = root
            .descendant_for_byte_range(target, target + "target".len())
            .and_then(|mut node| {
                loop {
                    if node.kind() == "declaration" {
                        break Some(node);
                    }
                    node = node.parent()?;
                }
            })
            .expect("declaration after the displaced terminator");
        let conditional = declaration
            .parent()
            .filter(|node| node.kind() == "preproc_ifdef")
            .expect("damaged inner conditional");
        let outer = conditional
            .parent()
            .filter(|node| node.kind() == "preproc_ifdef")
            .expect("ordinary outer include guard");
        let terminator = cpp_displaced_preprocessor_terminator(conditional)
            .expect("structured displaced #endif");
        assert_eq!(node_text(terminator, damaged), "#endif");
        assert!(terminator.end_byte() <= declaration.start_byte());
        assert!(!preprocessor_conditional_contains_descendant(
            conditional,
            declaration
        ));
        assert!(cpp_displaced_preprocessor_terminator(outer).is_none());
        assert!(preprocessor_conditional_contains_descendant(
            outer,
            declaration
        ));

        let tree = parse(guarded);
        let conditional = tree
            .root_node()
            .named_child(0)
            .filter(|node| node.kind() == "preproc_ifdef")
            .expect("ordinary conditional");
        let declaration = conditional
            .named_children(&mut conditional.walk())
            .find(|node| node.kind() == "declaration")
            .expect("guarded declaration");
        assert!(cpp_displaced_preprocessor_terminator(conditional).is_none());
        assert!(preprocessor_conditional_contains_descendant(
            conditional,
            declaration
        ));

        let damaged_alternative = format!(
            "#ifndef NO_FEATURE\nvoid enabled(void) {{}}\n#else\nvoid disabled(void) {{\n{}\n}}\n#endif\n",
            "UNUSED(value)\n".repeat(64)
        );
        let tree = parse(&damaged_alternative);
        let conditional = tree
            .root_node()
            .named_child(0)
            .filter(|node| node.kind() == "preproc_ifdef")
            .expect("outer conditional with an alternative");
        assert!(conditional.has_error());
        assert!(conditional.child_by_field_name("alternative").is_some());
        assert!(
            conditional
                .child(conditional.child_count() - 1)
                .is_some_and(|child| child.kind() == "#endif" && !child.is_missing())
        );
        assert!(cpp_displaced_preprocessor_terminator(conditional).is_none());

        let split_declaration = "struct Node;\n\ntypedef\n  #ifdef FEATURE_X\n    struct Node *\n  #else\n    UInt32\n  #endif\n  NodeRef;\n\nstatic int target(void) { return 1; }\n#ifdef LATER\nint later;\n#endif\n";
        let tree = parse(split_declaration);
        let root = tree.root_node();
        let conditional = root
            .named_children(&mut root.walk())
            .find(|node| node.kind() == "preproc_ifdef" && node.start_position().row == 3)
            .expect("split declaration conditional");
        let target = split_declaration
            .find("static int target")
            .expect("target byte");
        let boundary =
            cpp_displaced_preprocessor_boundary(conditional).expect("split declaration boundary");
        assert!(boundary.end_byte <= target, "{boundary:?}");
        assert_eq!(boundary.end_line, 9, "{boundary:?}");
        let target_node = root
            .descendant_for_byte_range(target, target + "static".len())
            .expect("target node");
        assert!(!preprocessor_conditional_contains_descendant(
            conditional,
            target_node
        ));
    }

    #[test]
    fn fragmented_reference_guard_is_recovered() {
        let source = "#if HAVE_ONE && HAVE_TWO\nstatic int helper(int value) { return value; }\n#endif\n\nint fragmented(int value) {\n    if (value == 0) {\n        return 0;\n#if HAVE_ONE && HAVE_TWO\n    } else if (value == 1) {\n        return helper(value);\n#endif\n    }\n    return 0;\n}\n";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .expect("C++ grammar");
        let tree = parser.parse(source, None).expect("fixture tree");
        let start = source.rfind("helper").expect("reference byte");
        let node = tree
            .root_node()
            .descendant_for_byte_range(start, start + "helper".len())
            .expect("reference node");
        let mut expected = HashSet::default();
        expected.insert(PreprocessorGuard::Boolean(BooleanGuardExpression::All(
            vec![
                BooleanGuardExpression::Truthy("HAVE_ONE".to_string()),
                BooleanGuardExpression::Truthy("HAVE_TWO".to_string()),
            ],
        )));
        assert_eq!(preprocessor_guard_environment(node, source), Some(expected));
    }

    #[test]
    fn split_language_linkage_wrapper_does_not_contradict_later_c_branch() {
        let source = r#"#ifdef _WIN32
#if defined(__cplusplus)
extern "C"
#endif
int platform_api(void);
#endif

#ifdef _WIN32
static int entropy_target(void) { return 0; }
#else
#ifdef HAVE_COMMON_RANDOM
static int other_target(void) { return 0; }
#elif defined(HAVE_GETENTROPY)
static int entropy_target(void) { return 1; }
static int use_entropy(void) { return entropy_target(); }
#endif
#endif
"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .expect("C++ grammar");
        let tree = parser.parse(source, None).expect("fixture tree");
        let start = source.rfind("entropy_target()").expect("reference");
        let node = tree
            .root_node()
            .descendant_for_byte_range(start, start + "entropy_target".len())
            .expect("reference node");
        let guards = preprocessor_guard_environment(node, source).expect("active C branch");
        assert!(
            guards.contains(&PreprocessorGuard::Undefined("_WIN32".to_string())),
            "{guards:#?}"
        );
        assert!(
            guards.contains(&PreprocessorGuard::Undefined(
                "HAVE_COMMON_RANDOM".to_string()
            )),
            "{guards:#?}"
        );
        assert!(
            guards.contains(&PreprocessorGuard::Defined("HAVE_GETENTROPY".to_string())),
            "{guards:#?}"
        );
        assert!(
            !guards.contains(&PreprocessorGuard::Defined("_WIN32".to_string())),
            "the malformed linkage wrapper must not impose its stale guard: {guards:#?}"
        );
    }

    #[test]
    fn ordinary_macro_role_distinguishes_conditional_body_from_directive_tokens() {
        let source = "#define KEY 42\n#ifdef ENABLE_KEYS\nint classify(int value) {\n    switch (value) {\n        case KEY: return 1;\n        default: return 0;\n    }\n}\n#endif\n";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .expect("C++ grammar");
        let tree = parser.parse(source, None).expect("fixture tree");
        let root = tree.root_node();
        let node_at = |text: &str, start: usize| {
            root.descendant_for_byte_range(start, start + text.len())
                .expect("token node")
        };

        let key_start = source.find("case KEY").expect("case label") + "case ".len();
        let guard_start = source.find("ENABLE_KEYS").expect("guard name");
        assert!(is_ordinary_macro_reference_node(node_at("KEY", key_start)));
        assert!(!is_ordinary_macro_reference_node(node_at(
            "ENABLE_KEYS",
            guard_start,
        )));
    }

    #[test]
    fn bare_macro_guard_is_implied_by_a_stronger_conjunction() {
        let source = "#if HAVE_ARM_NEON\nstatic int target(void) { return 1; }\n#endif\n#if HAVE_ARM_NEON && ENABLE_FAST_PATH\nint use(void) { return target(); }\n#endif\n";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .expect("C++ grammar");
        let tree = parser.parse(source, None).expect("fixture tree");
        let root = tree.root_node();
        let definition_start = source.find("target(void)").expect("definition");
        let reference_start = source.rfind("target()").expect("reference");
        let definition = root
            .descendant_for_byte_range(definition_start, definition_start + "target".len())
            .expect("definition node");
        let reference = root
            .descendant_for_byte_range(reference_start, reference_start + "target".len())
            .expect("reference node");
        let required =
            preprocessor_guard_environment(definition, source).expect("definition guard");
        let active = preprocessor_guard_environment(reference, source).expect("reference guard");
        assert!(guard_requirements_hold_at_reference(
            &required,
            Some(&active)
        ));
    }

    #[test]
    fn g_autoptr_assignment_shape_recovers_only_the_named_macro_declarator() {
        let source = "g_autoptr(FuChunkArray) self = make_array();";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .expect("C++ grammar");
        let tree = parser.parse(source, None).expect("fixture tree");
        let statement = tree.root_node().named_child(0).expect("statement");
        let binding =
            recognized_c_macro_declarator_binding(statement, source).expect("g_autoptr binding");
        assert_eq!(binding.name, "self");
        assert_eq!(binding.type_name, "FuChunkArray");
        assert_eq!(binding.pointer_depth, 1);

        let near_miss = "holder(FuChunkArray) self = make_array();";
        let tree = parser.parse(near_miss, None).expect("near-miss tree");
        let statement = tree.root_node().named_child(0).expect("statement");
        assert!(recognized_c_macro_declarator_binding(statement, near_miss).is_none());
    }

    #[test]
    fn boolean_guard_normalization_proves_equivalence_and_implication() {
        let windows = BooleanGuardExpression::Defined("WIN32".to_string());
        let cygwin = BooleanGuardExpression::Defined("CYGWIN".to_string());
        let negated_windows_branch =
            BooleanGuardExpression::all([windows.clone(), cygwin.negated()]).negated();
        let portable = BooleanGuardExpression::any([windows.negated(), cygwin]);
        assert_eq!(negated_windows_branch, portable);

        let missing_a = BooleanGuardExpression::Undefined("A".to_string());
        let missing_b = BooleanGuardExpression::Undefined("B".to_string());
        let missing_c = BooleanGuardExpression::Undefined("C".to_string());
        let fallback_branch = BooleanGuardExpression::any([missing_a.clone(), missing_b.clone()]);
        let fallback_declaration = BooleanGuardExpression::any([missing_a, missing_b, missing_c]);
        assert!(fallback_branch.implies(&fallback_declaration));
        assert!(
            BooleanGuardExpression::Truthy("FEATURE".to_string())
                .implies(&BooleanGuardExpression::Defined("FEATURE".to_string()))
        );
        assert!(
            BooleanGuardExpression::Undefined("FEATURE".to_string())
                .implies(&BooleanGuardExpression::Falsy("FEATURE".to_string()))
        );
        assert!(
            !BooleanGuardExpression::Defined("FEATURE".to_string())
                .implies(&BooleanGuardExpression::Truthy("FEATURE".to_string()))
        );
        assert!(!fallback_declaration.implies(&fallback_branch));
    }

    #[test]
    fn c_keyword_argument_recovery_requires_an_enclosing_displaced_parameter() {
        let source = "static int helper(const char *left, wchar_t *right) { return 0; }\nint caller(wchar_t *template) {\n    return helper(NULL, template); /* bound */\n}\nint unbound(void) {\n    return helper(NULL, template); /* unbound */\n}\n";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .expect("C++ grammar");
        let tree = parser.parse(source, None).expect("fixture tree");
        let root = tree.root_node();
        let call = |marker: &str| {
            let start = source.find(marker).expect("call marker");
            let mut node = root
                .descendant_for_byte_range(start, start + "helper".len())
                .expect("call name node");
            loop {
                if node.kind() == "call_expression" {
                    break node;
                }
                node = node.parent().expect("call expression ancestor");
            }
        };
        let c_file = ProjectFile::new(std::env::temp_dir(), "keyword-argument.c");
        let cpp_file = ProjectFile::new(std::env::temp_dir(), "keyword-argument.cpp");
        let keyword_call = call("helper(NULL, template); /* bound */");
        let keyword_arguments = keyword_call
            .child_by_field_name("arguments")
            .expect("keyword argument list");
        assert_eq!(
            recovered_c_keyword_argument_count(&c_file, keyword_call, keyword_arguments, source),
            1
        );
        assert_eq!(
            recovered_c_keyword_argument_count(&cpp_file, keyword_call, keyword_arguments, source),
            0
        );

        let unbound_call = call("helper(NULL, template); /* unbound */");
        let unbound_arguments = unbound_call
            .child_by_field_name("arguments")
            .expect("unbound argument list");
        assert_eq!(
            recovered_c_keyword_argument_count(&c_file, unbound_call, unbound_arguments, source),
            0
        );
    }

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

/// Comparator laws for the total C++ lookup order introduced by #1876.
///
/// `sort_lookup_units` is the single tie-break the C++ resolver applies before
/// any "first wins" selection (template families in #1836, the visible
/// identifier index, the type-candidate lists). If its comparator is not a
/// total order over CodeUnit identity, some pair stays tied and the survivor
/// falls back to the order the units arrived in -- which is FxHash iteration
/// order over keys whose hash covers the absolute workspace root. That is the
/// exact mechanism behind #1836 and the #414 / #432 heisenbug, so the laws are
/// checked generatively rather than on one hand-picked list.
///
/// CodeUnit identity is `source`, `kind`, `fq`, `package_segment_count`,
/// `signature` and `synthetic` (see `impl PartialEq for CodeUnit`); a CodeUnit
/// carries no range, so declaration ranges are covered by the workspace-level
/// property in `tests/suite_analyzers/determinism_properties.rs` instead.
#[cfg(test)]
mod lookup_order_properties {
    use super::*;
    use proptest::prelude::*;

    /// Segment spellings the C++ extractor and the shared renderer actually
    /// produce, including the `$`-joined nested spellings and non-ASCII
    /// identifiers that a byte-wise comparison has to keep apart.
    const ATOMS: [&str; 9] = ["a", "b", "A", "a$b", "a$", "$a", "ab", "naïve", "識別子"];
    const REL_PATHS: [&str; 3] = ["a.cpp", "b.cpp", "sub/a.cpp"];
    /// Two roots so the order is pinned across workspaces as well as inside
    /// one: the root path is precisely the byte string that used to leak into
    /// iteration order.
    const ROOT_NAMES: [&str; 2] = ["ws", "ws_much_longer_root_name"];
    const SIGNATURES: [Option<&str>; 3] = [None, Some("()"), Some("(int)")];
    const KINDS: [CodeUnitType; 6] = [
        CodeUnitType::Class,
        CodeUnitType::Function,
        CodeUnitType::Field,
        CodeUnitType::Module,
        CodeUnitType::Macro,
        CodeUnitType::FileScope,
    ];

    /// Where one unit sits relative to another under the comparator that
    /// `sort_lookup_units` owns.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum ProbedOrder {
        Before,
        Tied,
        After,
        /// Both directions reported "strictly first": the comparator is not
        /// dual, and no sort over it can be order-independent.
        Contradictory,
    }

    impl ProbedOrder {
        fn mirror(self) -> Self {
            match self {
                ProbedOrder::Before => ProbedOrder::After,
                ProbedOrder::After => ProbedOrder::Before,
                other => other,
            }
        }

        /// -1 / 0 / +1, so transitivity reads as the `<= 0` law.
        fn signum(self) -> i8 {
            match self {
                ProbedOrder::Before => -1,
                ProbedOrder::Tied => 0,
                ProbedOrder::After => 1,
                ProbedOrder::Contradictory => panic!("probed a non-dual comparator"),
            }
        }
    }

    /// Read the comparator through its only caller.
    ///
    /// `sort_lookup_units` is a stable sort, so for a two-element slice the
    /// output says exactly whether the comparator put the second element
    /// strictly first. Sorting both arrangements of one pair therefore reports
    /// the comparator's verdict in both directions, including the contradictory
    /// case a single sort would hide.
    fn probe_order(left: &CodeUnit, right: &CodeUnit) -> ProbedOrder {
        if left == right {
            // A stable sort cannot distinguish two equal values, and `Equal` is
            // the only verdict a total order can give them.
            return ProbedOrder::Tied;
        }
        let mut forward = vec![left.clone(), right.clone()];
        sort_lookup_units(&mut forward);
        let mut backward = vec![right.clone(), left.clone()];
        sort_lookup_units(&mut backward);
        let left_first = backward[0] == *left;
        let right_first = forward[0] == *right;
        match (left_first, right_first) {
            (true, true) => ProbedOrder::Contradictory,
            (true, false) => ProbedOrder::Before,
            (false, true) => ProbedOrder::After,
            (false, false) => ProbedOrder::Tied,
        }
    }

    /// `(kind, text)` per segment. `CodeUnit`'s own `Debug` prints interned
    /// segment IDs, which are process-local and say nothing about a failure.
    fn fq_segments(unit: &CodeUnit) -> Vec<(&'static str, &'static str)> {
        let interner = segment_interner();
        unit.fq()
            .segments()
            .iter()
            .map(|&id| {
                let (text, kind) = interner.resolve(id);
                (kind.name(), text)
            })
            .collect()
    }

    fn code_unit_strategy() -> impl Strategy<Value = CodeUnit> {
        (
            0..ROOT_NAMES.len(),
            0..REL_PATHS.len(),
            0..KINDS.len(),
            prop::collection::vec((0..ATOMS.len(), 0..SegmentKind::ALL.len()), 1..=3),
            0..3usize,
            0..SIGNATURES.len(),
            any::<bool>(),
        )
            .prop_map(
                |(root, rel_path, kind, segments, package_prefix, signature, synthetic)| {
                    let source = ProjectFile::new(
                        std::env::temp_dir().join(ROOT_NAMES[root]),
                        REL_PATHS[rel_path],
                    );
                    let interner = segment_interner();
                    let mut fq = FqName::new();
                    for (atom, segment_kind) in &segments {
                        fq.push(interner.intern(ATOMS[*atom], SegmentKind::ALL[*segment_kind]));
                    }
                    // `from_fq` requires a non-empty declaration tail.
                    let package_segment_count = package_prefix % fq.len();
                    CodeUnit::from_fq(
                        source,
                        KINDS[kind],
                        fq,
                        package_segment_count,
                        SIGNATURES[signature].map(str::to_string),
                        synthetic,
                    )
                },
            )
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// Reflexivity and duality: a unit ties with itself, and no pair is
        /// strictly first in both directions.
        #[test]
        fn lookup_order_is_reflexive_and_dual(
            left in code_unit_strategy(),
            right in code_unit_strategy(),
        ) {
            prop_assert_eq!(
                probe_order(&left, &left),
                ProbedOrder::Tied,
                "a unit must tie with itself: {:?}",
                left
            );
            let forward = probe_order(&left, &right);
            prop_assert_ne!(
                forward,
                ProbedOrder::Contradictory,
                "comparator put each of these strictly first: left={:?} right={:?}",
                left,
                right
            );
            prop_assert_eq!(
                probe_order(&right, &left),
                forward.mirror(),
                "compare(b, a) must reverse compare(a, b): left={:?} right={:?}",
                left,
                right
            );
        }

        /// Transitivity: `a <= b` and `b <= c` imply `a <= c`.
        #[test]
        fn lookup_order_is_transitive(
            a in code_unit_strategy(),
            b in code_unit_strategy(),
            c in code_unit_strategy(),
        ) {
            let ab = probe_order(&a, &b);
            let bc = probe_order(&b, &c);
            let ac = probe_order(&a, &c);
            for (probed, pair) in [(ab, "a,b"), (bc, "b,c"), (ac, "a,c")] {
                prop_assert_ne!(
                    probed,
                    ProbedOrder::Contradictory,
                    "comparator is not dual over {}: a={:?} b={:?} c={:?}",
                    pair,
                    a,
                    b,
                    c
                );
            }
            if ab.signum() <= 0 && bc.signum() <= 0 {
                prop_assert!(
                    ac.signum() <= 0,
                    "transitivity broken: a<=b ({:?}) and b<=c ({:?}) but a?c is {:?}; \
                     a={:?} b={:?} c={:?}",
                    ab,
                    bc,
                    ac,
                    a,
                    b,
                    c
                );
            }
        }

        /// The property #1876 exists for: only identical identities may tie.
        /// A tie between distinct units is the residual hash-order dependence.
        #[test]
        fn lookup_order_separates_distinct_identities(
            left in code_unit_strategy(),
            right in code_unit_strategy(),
        ) {
            if probe_order(&left, &right) == ProbedOrder::Tied {
                prop_assert_eq!(
                    &left,
                    &right,
                    "distinct identities tied, so their order is whatever order they \
                     arrived in: left_segments={:?} right_segments={:?}",
                    fq_segments(&left),
                    fq_segments(&right)
                );
            }
        }

        /// The consequence the resolver relies on: the sorted list is a
        /// function of the SET of units, not of the order they were pushed in.
        #[test]
        fn lookup_sort_is_permutation_invariant(
            units in prop::collection::vec(code_unit_strategy(), 1..=8),
        ) {
            let mut sorted = units.clone();
            sort_lookup_units(&mut sorted);
            for rotation in 0..units.len() {
                for reversed in [false, true] {
                    let mut permuted = units.clone();
                    permuted.rotate_left(rotation);
                    if reversed {
                        permuted.reverse();
                    }
                    sort_lookup_units(&mut permuted);
                    prop_assert_eq!(
                        &permuted,
                        &sorted,
                        "sorting a permutation gave a different list \
                         (rotation={}, reversed={}): input={:?}",
                        rotation,
                        reversed,
                        units
                    );
                }
            }
        }
    }
}
