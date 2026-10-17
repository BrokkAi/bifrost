//! Query-time Rust type facts from structure, the resolver, and the reviewed
//! std fact table (#3757).
//!
//! Three consumers read them: the inert-drop proof below, the receiver type a
//! Rust method call's external identity is minted from
//! ([`rust_method_receiver_owner`]), and the std operations the taint compiler
//! installs as built-in call models ([`rust_std_builtin_call`]).
//!
//! The Rust semantic adapter lowers one file at a time without the resolver.
//! When an implicit `Drop` it cannot type destroys only parameters and `let`
//! bindings, it publishes the omission with the `InertDropGlue` obligation, and
//! the workspace oracle answers that obligation here with
//! [`procedure_drops_run_no_user_code`].
//!
//! A type is proven inert -- its drop glue runs no user code -- only from:
//!
//! - structure: a reference, raw pointer, primitive, `()`, `!`, or a tuple or
//!   array of inert types;
//! - a reviewed std prelude type (`RUST_STD_TYPE_FACTS`) whose written name
//!   the resolver proves is the `std` or `core` prelude item, with inert type
//!   arguments;
//! - a workspace struct or enum the resolver names, with no type parameters
//!   and no attributes (a derive or attribute macro may implement `Drop`),
//!   whose fields are inert and for which the analyzer indexes no `drop`
//!   member. `Drop` may be implemented only in the type's own crate, which the
//!   workspace indexes.
//!
//! An expression's type comes from literals, the declared type of the
//! parameter or `let` a name resolves to, the declared return type of the
//! workspace function a call resolves to, an activated model's exact
//! per-call return signature, and the reviewed std method, operator, and
//! constructor facts. Anything else leaves the proof open and the gap stands;
//! nothing here is inferred from spelling alone.
//!
//! Expression classes and modeled call shapes are memoized only while one
//! query proves one prepared source. Those memos and every answer are dropped
//! with the query; all other facts come from the prepared trees and point
//! resolver lookups.

use std::ops::Range as ByteRange;
use std::sync::{Arc, OnceLock};
#[cfg(test)]
use std::{cell::Cell, time::Instant};
use std::{cell::RefCell, collections::HashMap};

use brokk_bifrost_rust::graph_support::rust_path_segments;
use brokk_bifrost_rust::prelude::{
    RUST_STD_ASSOCIATED_FACTS, RUST_STD_METHOD_FACTS, RUST_STD_STRING_ADD_STR,
    RustStdAssociatedFact, RustStdReceiver, RustStdValue, rust_std_associated_fact,
    rust_std_constructor_fact, rust_std_method_fact, rust_std_type_fact,
};
use brokk_bifrost_rust::structural::call_function_target;
use brokk_bifrost_rust::syntax::{item_has_path_attribute, outer_attributes};
use tree_sitter::{Node, Tree};

use brokk_bifrost_core::analyzer::CodeUnitIndex;
use brokk_bifrost_core::analyzer::structural::native_obligation::{
    NativeResultObligation, NativeResultObligationBasis,
};

use super::RustAnalyzer;
use super::semantic::named_children;
use crate::analyzer::languages::{
    BoundedReceiverQuery, ExternalCalleeFileEvidence, ExternalCalleeSite,
};
use crate::analyzer::lexical_definitions::{LexicalBindingResolution, resolve_lexical_binding};
use crate::analyzer::semantic_model::{
    SemanticModelCallApplication, SemanticModelCallableKey, TypeRef,
};
use crate::analyzer::tree_sitter_analyzer::PreparedSyntaxTree;
use crate::analyzer::usages::get_definition::{
    BoundedResolution, DefinitionLookupOutcome, DefinitionLookupStatus, ResolvedReferenceSite,
    UnindexedClaimKind,
};
use crate::analyzer::usages::receiver_analysis::INTERACTIVE_TYPE_LOOKUP_BUDGET;
use crate::analyzer::{
    AnalyzerQueryScope, CodeUnit, IAnalyzer, Language, ProjectFile, QueryScope, Range,
    resolve_analyzer,
};

/// How many nested type or binding hops one proof follows. The proof fails
/// closed past it, which bounds the otherwise recursive descent.
const PROOF_DEPTH: usize = 8;

/// Completion describes reuse only. Even an incomplete attempt retains its
/// ordinary value so existing proof callers keep exactly their prior behavior.
#[derive(Debug, Clone)]
pub(crate) enum RustProofAttempt<T> {
    Complete(Option<T>),
    Incomplete {
        value: Option<T>,
        reason: &'static str,
    },
}

impl<T> RustProofAttempt<T> {
    pub(crate) fn into_value(self) -> Option<T> {
        match self {
            Self::Complete(value) | Self::Incomplete { value, .. } => value,
        }
    }
}

thread_local! {
    // Each entry belongs to one synchronous proof attempt. Nested external
    // identity proofs run on the same worker and poison every enclosing
    // attempt when they encounter an unfinished path. Nothing survives a query.
    static PROOF_ATTEMPTS: RefCell<Vec<Option<&'static str>>> = const { RefCell::new(Vec::new()) };
}

pub(crate) fn incomplete_proof(reason: &'static str) {
    PROOF_ATTEMPTS.with(|attempts| {
        for attempt in attempts.borrow_mut().iter_mut() {
            attempt.get_or_insert(reason);
        }
    });
}

pub(crate) fn observe_proof_resolution(resolution: &BoundedResolution<DefinitionLookupOutcome>) {
    match resolution {
        BoundedResolution::Exceeded { .. } => incomplete_proof("exceeded"),
        BoundedResolution::Cancelled { .. } => incomplete_proof("cancelled"),
        BoundedResolution::Complete { value, .. } => {
            if !matches!(
                value.status,
                DefinitionLookupStatus::Resolved
                    | DefinitionLookupStatus::NoDefinition
                    | DefinitionLookupStatus::UnresolvableImportBoundary
                    | DefinitionLookupStatus::Ambiguous
            ) {
                incomplete_proof(value.status.as_str());
            }
        }
    }
}

pub(crate) fn completed_proof<T>(
    cancellation: Option<&crate::CancellationToken>,
    proof: impl FnOnce() -> Option<T>,
) -> RustProofAttempt<T> {
    struct Attempt;
    impl Drop for Attempt {
        fn drop(&mut self) {
            PROOF_ATTEMPTS.with(|attempts| {
                attempts
                    .borrow_mut()
                    .pop()
                    .expect("active Rust proof attempt");
            });
        }
    }
    PROOF_ATTEMPTS.with(|attempts| attempts.borrow_mut().push(None));
    let guard = Attempt;
    let value = proof();
    if cancellation.is_some_and(|token| token.is_cancelled() || token.soft_deadline_passed()) {
        incomplete_proof("cancelled_or_deadline");
    }
    let reason = PROOF_ATTEMPTS
        .with(|attempts| *attempts.borrow().last().expect("active Rust proof attempt"));
    drop(guard);
    match reason {
        Some(reason) => RustProofAttempt::Incomplete { value, reason },
        None => RustProofAttempt::Complete(value),
    }
}

/// What the proof knows about one value's type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RustValueClass {
    /// A `&str`: a string literal, or a binding declared `&str` or
    /// `&mut str`.
    Str,
    /// A `String`, proven through the reviewed std facts.
    String,
    /// The `Result<String, _>` returned by the reviewed `std::env::var`
    /// declaration. The semantic model records the outer `Result` return but
    /// intentionally does not encode its generic payload, so this class keeps
    /// that structured std fact available to the following `unwrap` call.
    EnvVarResult,
    /// Some other type whose drop glue runs no user code.
    Inert,
    /// Not proven.
    Unknown,
}

impl RustValueClass {
    fn is_inert(self) -> bool {
        self != Self::Unknown
    }

    fn from_std(value: RustStdValue) -> Self {
        match value {
            RustStdValue::StdType("String") => Self::String,
            RustStdValue::StdType(name) => {
                // Every other reviewed std type carries type arguments, which
                // a bare std value does not name.
                debug_assert!(rust_std_type_fact(name).is_some());
                Self::Unknown
            }
            RustStdValue::Primitive(_) => Self::Inert,
        }
    }
}

type RustModeledCallShape = (String, String, bool, usize);

/// One file's exact prepared source, as the proof reads it.
struct RustSource {
    file: ProjectFile,
    prepared: Arc<PreparedSyntaxTree>,
    expression_classes: RefCell<HashMap<(usize, usize), RustValueClass>>,
    modeled_call_shapes: RefCell<HashMap<(usize, usize), Option<RustModeledCallShape>>>,
    #[cfg(test)]
    expression_class_evaluations: Cell<usize>,
    #[cfg(test)]
    expression_class_evaluation_limit: Cell<Option<usize>>,
    #[cfg(test)]
    modeled_call_shape_evaluations: Cell<usize>,
    #[cfg(test)]
    modeled_call_shape_evaluation_limit: Cell<Option<usize>>,
}

impl RustSource {
    fn text(&self) -> &str {
        self.prepared.source()
    }

    fn tree(&self) -> &Tree {
        self.prepared.tree()
    }

    fn node_text(&self, node: Node<'_>) -> Option<&str> {
        self.text().get(node.byte_range())
    }
}

/// The resolver and analyzer access one query's proofs share.
pub(crate) struct RustTypeProof<'a, R: RustTypeProofResolver = FactoryRustTypeProofResolver<'a>> {
    analyzer: &'a dyn IAnalyzer,
    rust: &'a RustAnalyzer,
    resolver: R,
}

pub(crate) trait RustTypeProofResolver {
    fn resolve(
        &self,
        query: BoundedReceiverQuery<'_>,
    ) -> BoundedResolution<DefinitionLookupOutcome>;

    fn external_call_identity(
        &self,
        file: &ProjectFile,
        source: &str,
        tree: &Tree,
        site: &ResolvedReferenceSite,
        callee_start_byte: usize,
    ) -> Option<crate::analyzer::semantic::ResolverOwnedExternalCalleeIdentity>;

    fn cancellation(&self) -> Option<&crate::CancellationToken>;
}

pub(crate) struct FactoryRustTypeProofResolver<'a> {
    analyzer: &'a dyn IAnalyzer,
    definition_operation_factory:
        OnceLock<Option<super::native_points::RustDefinitionOperationFactory<'a>>>,
}

impl<'a> FactoryRustTypeProofResolver<'a> {
    fn factory(&self) -> Option<&super::native_points::RustDefinitionOperationFactory<'a>> {
        self.definition_operation_factory
            .get_or_init(|| {
                let cancellation = crate::CancellationToken::default();
                super::native_points::RustDefinitionOperationFactory::new(
                    self.analyzer,
                    &cancellation,
                )
            })
            .as_ref()
    }
}

impl RustTypeProofResolver for FactoryRustTypeProofResolver<'_> {
    fn resolve(
        &self,
        query: BoundedReceiverQuery<'_>,
    ) -> BoundedResolution<DefinitionLookupOutcome> {
        match self.factory() {
            Some(factory) => factory.resolve_bounded(query),
            None => super::native_points::resolve_rust_definition_bounded(query),
        }
    }

    fn external_call_identity(
        &self,
        file: &ProjectFile,
        source: &str,
        tree: &Tree,
        site: &ResolvedReferenceSite,
        callee_start_byte: usize,
    ) -> Option<crate::analyzer::semantic::ResolverOwnedExternalCalleeIdentity> {
        resolve_external_call_identity(
            self.analyzer,
            file,
            source,
            tree,
            site,
            callee_start_byte,
            self.factory(),
            None,
            None,
        )
    }

    fn cancellation(&self) -> Option<&crate::CancellationToken> {
        None
    }
}

struct SelectedRustTypeProofResolver<'analyzer, 'factory, 'selection, 'operation, 'cancellation> {
    analyzer: &'analyzer dyn IAnalyzer,
    factory: &'factory super::native_points::RustDefinitionOperationFactory<'analyzer>,
    operation: RefCell<
        &'operation mut crate::analyzer::store::resolution_operation::SelectedResolutionOperation<
            'analyzer,
            'selection,
        >,
    >,
    cancellation: Option<&'cancellation crate::CancellationToken>,
}

impl RustTypeProofResolver for SelectedRustTypeProofResolver<'_, '_, '_, '_, '_> {
    fn resolve(
        &self,
        query: BoundedReceiverQuery<'_>,
    ) -> BoundedResolution<DefinitionLookupOutcome> {
        let mut operation = self.operation.borrow_mut();
        self.factory.resolve(&mut operation, query)
    }

    fn external_call_identity(
        &self,
        file: &ProjectFile,
        source: &str,
        tree: &Tree,
        site: &ResolvedReferenceSite,
        callee_start_byte: usize,
    ) -> Option<crate::analyzer::semantic::ResolverOwnedExternalCalleeIdentity> {
        let mut operation = self.operation.borrow_mut();
        resolve_external_call_identity(
            self.analyzer,
            file,
            source,
            tree,
            site,
            callee_start_byte,
            Some(self.factory),
            Some(&mut **operation),
            self.cancellation,
        )
    }

    fn cancellation(&self) -> Option<&crate::CancellationToken> {
        self.cancellation
    }
}

#[allow(clippy::too_many_arguments)]
fn resolve_external_call_identity<'analyzer, 'factory, 'selection>(
    analyzer: &'analyzer dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    site: &ResolvedReferenceSite,
    callee_start_byte: usize,
    factory: Option<&'factory super::native_points::RustDefinitionOperationFactory<'analyzer>>,
    mut operation: Option<
        &mut crate::analyzer::store::resolution_operation::SelectedResolutionOperation<
            'analyzer,
            'selection,
        >,
    >,
    cancellation: Option<&crate::CancellationToken>,
) -> Option<crate::analyzer::semantic::ResolverOwnedExternalCalleeIdentity> {
    let scope = AnalyzerQueryScope::new(analyzer);
    let token = scope.token();
    super::external_calls::resolve_exact_rust_external_call_with_operation(
        analyzer,
        token,
        file,
        source,
        tree,
        site,
        || None,
        cancellation,
        factory,
        operation.as_deref_mut(),
    )
    .map(|(_, identity)| identity)
    .or_else(|| {
        let file_evidence = ExternalCalleeFileEvidence::default();
        let external_site = ExternalCalleeSite {
            source,
            tree,
            callee_start_byte,
            file_evidence: &file_evidence,
        };
        super::expand_rust_imported_external_callee_with_operation(
            analyzer,
            file,
            "",
            Some(&external_site),
            factory,
            operation,
        )
        .and_then(|callee| callee.external_callee_identity)
    })
}

/// The standard `Result` variant named by a pattern constructor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RustResultVariant {
    Ok,
    Err,
}

/// The language-native result obligation proof for one resolved Rust call
/// target. `Open` deliberately carries a stable transport reason rather than
/// collapsing an unresolved declaration into a clean result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RustNativeObligationProof {
    Obligation(NativeResultObligation),
    NoObligation,
    Open(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RustNativeReturnKind {
    FallibleResult,
    MustUseValue,
    OrdinaryValue,
    Open(&'static str),
}

/// Resolve a Rust pattern constructor to the standard-library `Result`
/// variant it names. Bare constructors require the resolver's prelude proof;
/// qualified constructors require the owner type to resolve to the standard
/// `Result` prelude item. A workspace declaration, import route, lexical
/// shadow, or unresolved lookup therefore stays open.
pub(crate) fn rust_standard_result_variant(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    constructor: ByteRange<usize>,
) -> Option<RustResultVariant> {
    let proof = RustTypeProof::new(analyzer)?;
    let rust_source = proof.source(file)?;
    if rust_source.text() != source {
        incomplete_proof("source_mismatch");
        return None;
    }
    let node = rust_source
        .tree()
        .root_node()
        .named_descendant_for_byte_range(constructor.start, constructor.end)
        .filter(|node| node.byte_range() == constructor)?;
    let variant_name = match node.kind() {
        "identifier" | "type_identifier" => {
            let name = rust_source.node_text(node)?;
            let fact = rust_std_constructor_fact(name)?;
            if fact.constructs != "Result" || fact.arity != 1 {
                return None;
            }
            standard_result_prelude_name(&proof, &rust_source, node, "value", name)?;
            Some(name)
        }
        "scoped_identifier" | "scoped_type_identifier" => {
            let name = node.child_by_field_name("name")?;
            let owner_path = node.child_by_field_name("path")?;
            let name = rust_source.node_text(name)?;
            let fact = rust_std_constructor_fact(name)?;
            if fact.constructs != "Result" || fact.arity != 1 {
                return None;
            }
            standard_result_type_path(&proof, &rust_source, owner_path)?;
            Some(name)
        }
        _ => None,
    }?;
    match variant_name {
        "Ok" => Some(RustResultVariant::Ok),
        "Err" => Some(RustResultVariant::Err),
        _ => None,
    }
}

fn standard_result_prelude_name<R: RustTypeProofResolver>(
    proof: &RustTypeProof<'_, R>,
    source: &RustSource,
    node: Node<'_>,
    namespace: &str,
    expected: &str,
) -> Option<String> {
    let outcome = proof.resolve(source, node)?;
    if prelude_item_of(&outcome, namespace).as_deref() == Some(expected) {
        return Some(expected.to_owned());
    }
    // A pattern constructor has a Pattern resolution site rather than the
    // ordinary value-reference site used by calls. The selected resolver
    // still proves the important negative facts at that site: no workspace
    // definition, lexical binding, or import claim. With the reviewed Result
    // constructor table, that boundary is the implicit core/std prelude.
    (outcome.status == DefinitionLookupStatus::UnresolvableImportBoundary
        && outcome.definitions.is_empty()
        && outcome.lexical_definition.is_none()
        && outcome
            .diagnostics
            .iter()
            .all(|diagnostic| diagnostic.claim.is_none()))
    .then(|| expected.to_owned())
}

fn standard_result_type_path<R: RustTypeProofResolver>(
    proof: &RustTypeProof<'_, R>,
    source: &RustSource,
    path: Node<'_>,
) -> Option<()> {
    let segments = rust_path_segments(path)?;
    let names = segments
        .iter()
        .map(|segment| source.node_text(*segment))
        .collect::<Option<Vec<_>>>()?;
    // `path` names the `Result` type itself: the owner of a variant path
    // (`std::result::Result` in `std::result::Result::Err`) or a whole type
    // path (`std::result::Result` in a return type).
    match names.as_slice() {
        ["Result"] => {
            standard_result_prelude_name(proof, source, segments[0], "type", "Result")?;
            Some(())
        }
        [root @ ("std" | "core"), "result", "Result"] => {
            let root_outcome = proof.resolve(source, segments[0])?;
            (root_outcome.definitions.is_empty()
                && root_outcome.lexical_definition.is_none()
                && !root_outcome
                    .diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.claim.is_some())
                && matches!(
                    root_outcome.status,
                    DefinitionLookupStatus::Incomplete
                        | DefinitionLookupStatus::UnresolvableImportBoundary
                )
                && source.node_text(segments[0]) == Some(root))
            .then_some(())
        }
        _ => None,
    }
}

impl<'a> RustTypeProof<'a, FactoryRustTypeProofResolver<'a>> {
    pub(crate) fn new(analyzer: &'a dyn IAnalyzer) -> Option<Self> {
        let rust = resolve_analyzer::<RustAnalyzer>(analyzer)?;
        Some(Self {
            analyzer,
            rust,
            resolver: FactoryRustTypeProofResolver {
                analyzer,
                definition_operation_factory: OnceLock::new(),
            },
        })
    }
}

impl<'a, R: RustTypeProofResolver> RustTypeProof<'a, R> {
    fn source(&self, file: &ProjectFile) -> Option<RustSource> {
        let scope = AnalyzerQueryScope::new(self.analyzer);
        let Some(prepared) = self.rust.prepared_syntax(scope.token(), file) else {
            incomplete_proof("source_unavailable");
            return None;
        };
        Some(RustSource {
            file: file.clone(),
            prepared,
            expression_classes: RefCell::new(HashMap::new()),
            modeled_call_shapes: RefCell::new(HashMap::new()),
            #[cfg(test)]
            expression_class_evaluations: Cell::new(0),
            #[cfg(test)]
            expression_class_evaluation_limit: Cell::new(None),
            #[cfg(test)]
            modeled_call_shape_evaluations: Cell::new(0),
            #[cfg(test)]
            modeled_call_shape_evaluation_limit: Cell::new(None),
        })
    }

    /// The resolver's complete answer for the name `node` spells.
    fn resolve(&self, source: &RustSource, node: Node<'_>) -> Option<DefinitionLookupOutcome> {
        // The resolver records a scoped path's reference at its last segment.
        let node = match node.kind() {
            "scoped_identifier" | "scoped_type_identifier" => node.child_by_field_name("name")?,
            _ => node,
        };
        let text = source.node_text(node)?.to_owned();
        let site = ResolvedReferenceSite {
            path: text.clone(),
            text,
            range: node_range(node),
            focus_start_byte: node.start_byte(),
            focus_end_byte: node.end_byte(),
        };
        let query = BoundedReceiverQuery {
            analyzer: self.analyzer,
            file: &source.file,
            source: source.text(),
            tree: Some(source.tree()),
            site: &site,
            budget: INTERACTIVE_TYPE_LOOKUP_BUDGET,
            cancellation: None,
        };
        let resolution = self.resolver.resolve(BoundedReceiverQuery {
            cancellation: self.resolver.cancellation(),
            ..query
        });
        observe_proof_resolution(&resolution);
        match resolution {
            BoundedResolution::Complete { value, .. } => Some(value),
            BoundedResolution::Exceeded { .. } | BoundedResolution::Cancelled { .. } => None,
        }
    }

    /// The `std` or `core` prelude item the name at `node` resolves to, when
    /// the resolver proves that and nothing else: no workspace declaration,
    /// no lexical binding, no `use` route, and exactly one prelude reason in
    /// `namespace` (`"type"` or `"value"`).
    fn prelude_item(&self, source: &RustSource, node: Node<'_>, namespace: &str) -> Option<String> {
        prelude_item_of(&self.resolve(source, node)?, namespace)
    }

    /// The one workspace declaration the name at `node` resolves to.
    fn workspace_definition(&self, source: &RustSource, node: Node<'_>) -> Option<CodeUnit> {
        let outcome = self.resolve(source, node)?;
        match (
            outcome.status,
            outcome.definitions.as_slice(),
            outcome.lexical_definition,
        ) {
            (DefinitionLookupStatus::Resolved, [definition], None) => Some(definition.clone()),
            _ => None,
        }
    }

    /// The declaration node of a workspace unit in its own file.
    fn declaration<'s>(&self, source: &'s RustSource, unit: &CodeUnit) -> Option<Node<'s>> {
        let ranges = self.rust.ranges_limited(unit, 2);
        let [range] = ranges.rows.as_slice() else {
            return None;
        };
        if !ranges.complete {
            return None;
        }
        let node = source
            .tree()
            .root_node()
            .named_descendant_for_byte_range(range.start_byte, range.end_byte)?;
        (node.byte_range() == (range.start_byte..range.end_byte)).then_some(node)
    }

    /// Return the trait method whose signature governs an implementation
    /// member, when the hierarchy index proves that relationship. Trait
    /// attributes are not inherited by the implementation AST, so native
    /// obligation proof must read the trait declaration itself.
    fn trait_signature_target(&self, target: &CodeUnit) -> Result<Option<CodeUnit>, &'static str> {
        if !target.is_function() {
            return Ok(None);
        }
        let scope = AnalyzerQueryScope::new(self.analyzer);
        let trait_owner = brokk_bifrost_rust::hierarchy::rust_trait_for_impl_member(
            self.rust,
            scope.token(),
            target,
        )
        .map_err(|_| "native_trait_signature_unknown")?;
        let Some(trait_owner) = trait_owner else {
            return Ok(None);
        };
        let candidates = self
            .rust
            .get_direct_children(&trait_owner)
            .into_iter()
            .filter(|child| child.is_function() && child.identifier() == target.identifier())
            .collect::<Vec<_>>();
        match candidates.as_slice() {
            [candidate] => Ok(Some(candidate.clone())),
            _ => Err("native_trait_signature_unknown"),
        }
    }

    /// Classify the declared result type of one Rust callable. The returned
    /// type is intentionally structural: aliases are followed only through
    /// workspace declarations, and an unresolved or generic type stays open.
    fn native_return_kind(
        &self,
        source: &RustSource,
        ty: Option<Node<'_>>,
        depth: usize,
    ) -> RustNativeReturnKind {
        let Some(ty) = ty else {
            return RustNativeReturnKind::OrdinaryValue;
        };
        if depth == 0 {
            incomplete_proof("depth_limit");
            return RustNativeReturnKind::Open("native_return_type_depth");
        }
        match ty.kind() {
            // These types carry no language-level `must_use` obligation of
            // their own. A declaration-level attribute is checked by the
            // caller after this classification.
            "primitive_type" | "unit_type" | "never_type" | "reference_type" | "pointer_type"
            | "tuple_type" | "array_type" | "function_type" | "raw_string_literal" => {
                RustNativeReturnKind::OrdinaryValue
            }
            "type_identifier" | "scoped_type_identifier" => {
                self.native_nominal_return_kind(source, ty, depth)
            }
            "generic_type" => {
                let Some(name) = ty.child_by_field_name("type") else {
                    return RustNativeReturnKind::Open("native_return_type_unknown");
                };
                self.native_nominal_return_kind(source, name, depth)
            }
            // `impl Trait`, `dyn Trait`, higher-ranked types, and any syntax
            // the grammar does not expose as a nominal declaration require a
            // reviewed model before a discarded value can be classified.
            _ => RustNativeReturnKind::Open("native_return_type_unknown"),
        }
    }

    fn native_nominal_return_kind(
        &self,
        source: &RustSource,
        name: Node<'_>,
        depth: usize,
    ) -> RustNativeReturnKind {
        if self.standard_result_type(source, name) {
            return RustNativeReturnKind::FallibleResult;
        }
        if let Some(unit) = self.workspace_definition(source, name) {
            return self.workspace_return_kind(&unit, depth - 1);
        }
        if self.external_result_alias(source, name) {
            return RustNativeReturnKind::FallibleResult;
        }
        if name.kind() == "type_identifier" && self.prelude_item(source, name, "type").is_some() {
            // The standard-library types which carry `#[must_use]` need a
            // reviewed model of their semantics. The Rust B4 lane claims no
            // such external type merely from its spelling.
            return RustNativeReturnKind::Open("native_std_type_unmodeled");
        }
        RustNativeReturnKind::Open("native_return_type_unresolved")
    }

    fn standard_result_type(&self, source: &RustSource, name: Node<'_>) -> bool {
        match name.kind() {
            "type_identifier" => {
                standard_result_prelude_name(self, source, name, "type", "Result").is_some()
            }
            "scoped_type_identifier" => standard_result_type_path(self, source, name).is_some(),
            _ => false,
        }
    }

    /// The resolver may expose an external alias without a materialized
    /// declaration. Accept only the exact standard Result aliases that the
    /// resolver names; an arbitrary `io::Result` remains open.
    fn external_result_alias(&self, source: &RustSource, name: Node<'_>) -> bool {
        let name_is_result = match name.kind() {
            "scoped_type_identifier" => {
                name.child_by_field_name("name")
                    .and_then(|last| source.node_text(last))
                    == Some("Result")
            }
            // An imported alias is represented by a bare type identifier. Its
            // resolver claim, rather than its spelling, is the proof that it
            // names one of the reviewed standard Result declarations.
            "type_identifier" => true,
            _ => false,
        };
        if !name_is_result {
            return false;
        }
        let Some(outcome) = self.resolve(source, name) else {
            return false;
        };
        outcome
            .diagnostics
            .iter()
            .filter_map(|diagnostic| diagnostic.claim.as_ref())
            .filter(|claim| {
                matches!(
                    claim.kind,
                    UnindexedClaimKind::ResolvedExternal | UnindexedClaimKind::ExternalBoundary
                )
            })
            .flat_map(|claim| claim.subjects.iter())
            .any(|subject| {
                matches!(
                    subject.as_str(),
                    "std::result::Result"
                        | "core::result::Result"
                        | "std::io::Result"
                        | "std.result.Result"
                        | "core.result.Result"
                        | "std.io.Result"
                )
            })
    }

    fn workspace_return_kind(&self, unit: &CodeUnit, depth: usize) -> RustNativeReturnKind {
        if depth == 0 {
            incomplete_proof("depth_limit");
            return RustNativeReturnKind::Open("native_return_type_depth");
        }
        let Some(source) = self.source(unit.source()) else {
            return RustNativeReturnKind::Open("native_return_type_source");
        };
        let Some(item) = self.declaration(&source, unit) else {
            return RustNativeReturnKind::Open("native_return_type_declaration");
        };
        if item.kind() == "type_item" {
            let kind =
                self.native_return_kind(&source, item.child_by_field_name("type"), depth - 1);
            return match kind {
                RustNativeReturnKind::FallibleResult => kind,
                RustNativeReturnKind::Open(reason) => RustNativeReturnKind::Open(reason),
                RustNativeReturnKind::MustUseValue | RustNativeReturnKind::OrdinaryValue
                    if item_has_path_attribute(item, source.text(), "must_use") =>
                {
                    RustNativeReturnKind::MustUseValue
                }
                _ => kind,
            };
        }
        if matches!(item.kind(), "struct_item" | "enum_item" | "union_item") {
            return if item_has_path_attribute(item, source.text(), "must_use") {
                RustNativeReturnKind::MustUseValue
            } else {
                RustNativeReturnKind::OrdinaryValue
            };
        }
        RustNativeReturnKind::Open("native_return_type_declaration")
    }

    fn native_obligation_for_target(
        &self,
        target: &CodeUnit,
        result_ordinal: u32,
    ) -> RustNativeObligationProof {
        if target.source().declaration_language() != Language::Rust {
            return RustNativeObligationProof::Open("native_target_language");
        }
        if result_ordinal != 0 {
            return RustNativeObligationProof::NoObligation;
        }
        let Some(source) = self.source(target.source()) else {
            return RustNativeObligationProof::Open("native_target_source");
        };
        let Some(item) = self.declaration(&source, target) else {
            return RustNativeObligationProof::Open("native_target_declaration");
        };
        let signature_target = match self.trait_signature_target(target) {
            Ok(signature_target) => signature_target,
            Err(reason) => return RustNativeObligationProof::Open(reason),
        };
        if let Some(signature_target) = signature_target {
            let Some(signature_source) = self.source(signature_target.source()) else {
                return RustNativeObligationProof::Open("native_trait_signature_source");
            };
            let Some(signature_item) = self.declaration(&signature_source, &signature_target)
            else {
                return RustNativeObligationProof::Open("native_trait_signature_declaration");
            };
            return self.native_obligation_for_declaration(
                &signature_source,
                signature_item,
                result_ordinal,
            );
        }
        self.native_obligation_for_declaration(&source, item, result_ordinal)
    }

    fn native_obligation_for_declaration(
        &self,
        source: &RustSource,
        item: Node<'_>,
        result_ordinal: u32,
    ) -> RustNativeObligationProof {
        let return_kind =
            self.native_return_kind(source, item.child_by_field_name("return_type"), PROOF_DEPTH);
        match return_kind {
            // Result is always B5, even if the callable or alias also carries
            // `#[must_use]`; the two policies must never double-report.
            RustNativeReturnKind::FallibleResult => {
                RustNativeObligationProof::Obligation(NativeResultObligation::fallible_status(
                    result_ordinal,
                    NativeResultObligationBasis::StaticSignature,
                ))
            }
            RustNativeReturnKind::Open(reason) => RustNativeObligationProof::Open(reason),
            RustNativeReturnKind::MustUseValue => {
                RustNativeObligationProof::Obligation(NativeResultObligation::must_use_value(
                    result_ordinal,
                    NativeResultObligationBasis::StaticSignature,
                ))
            }
            RustNativeReturnKind::OrdinaryValue => {
                if item_has_path_attribute(item, source.text(), "must_use") {
                    RustNativeObligationProof::Obligation(NativeResultObligation::must_use_value(
                        result_ordinal,
                        NativeResultObligationBasis::StaticSignature,
                    ))
                } else {
                    RustNativeObligationProof::NoObligation
                }
            }
        }
    }

    /// The class of the declared type `ty`, written in `source`.
    fn type_class(&self, source: &RustSource, ty: Node<'_>, depth: usize) -> RustValueClass {
        if depth == 0 {
            incomplete_proof("depth_limit");
            return RustValueClass::Unknown;
        }
        match ty.kind() {
            "reference_type" => {
                let referent = ty.child_by_field_name("type");
                if referent.is_some_and(|referent| {
                    referent.kind() == "primitive_type" && source.node_text(referent) == Some("str")
                }) {
                    RustValueClass::Str
                } else {
                    RustValueClass::Inert
                }
            }
            "pointer_type" | "primitive_type" | "unit_type" | "never_type" => RustValueClass::Inert,
            "tuple_type" | "array_type" => {
                let elements = if ty.kind() == "array_type" {
                    ty.child_by_field_name("element").into_iter().collect()
                } else {
                    named_children(ty)
                };
                if elements
                    .into_iter()
                    .all(|element| self.type_class(source, element, depth - 1).is_inert())
                {
                    RustValueClass::Inert
                } else {
                    RustValueClass::Unknown
                }
            }
            "type_identifier" | "scoped_type_identifier" | "generic_type" => {
                self.nominal_type_class(source, ty, depth)
            }
            _ => RustValueClass::Unknown,
        }
    }

    fn nominal_type_class(
        &self,
        source: &RustSource,
        ty: Node<'_>,
        depth: usize,
    ) -> RustValueClass {
        let (name, arguments) = if ty.kind() == "generic_type" {
            let Some(name) = ty.child_by_field_name("type") else {
                return RustValueClass::Unknown;
            };
            let arguments = ty
                .child_by_field_name("type_arguments")
                .map(named_children)
                .unwrap_or_default();
            (name, arguments)
        } else {
            (ty, Vec::new())
        };
        // A lifetime argument names no value and drops nothing.
        let arguments = arguments
            .into_iter()
            .filter(|argument| argument.kind() != "lifetime")
            .collect::<Vec<_>>();
        if name.kind() == "type_identifier"
            && let Some(prelude) = self.prelude_item(source, name, "type")
            && let Some(fact) = rust_std_type_fact(&prelude)
        {
            if arguments.len() != fact.type_arguments
                || !arguments
                    .iter()
                    .all(|argument| self.type_class(source, *argument, depth - 1).is_inert())
            {
                return RustValueClass::Unknown;
            }
            return if fact.name == "String" {
                RustValueClass::String
            } else {
                RustValueClass::Inert
            };
        }
        if self.standard_result_type(source, name) {
            return if arguments.len() == 2
                && arguments
                    .iter()
                    .all(|argument| self.type_class(source, *argument, depth - 1).is_inert())
            {
                RustValueClass::Inert
            } else {
                RustValueClass::Unknown
            };
        }
        if !arguments.is_empty() {
            return RustValueClass::Unknown;
        }
        match self.workspace_definition(source, name) {
            Some(unit) if self.workspace_type_is_inert(&unit, depth - 1) => RustValueClass::Inert,
            _ => RustValueClass::Unknown,
        }
    }

    /// Whether a workspace struct or enum's drop glue runs no user code.
    fn workspace_type_is_inert(&self, unit: &CodeUnit, depth: usize) -> bool {
        if depth == 0 {
            incomplete_proof("depth_limit");
        }
        if depth == 0 || !unit.is_class() {
            return false;
        }
        // `Drop` can be implemented only in the type's own crate, which the
        // workspace indexes; an indexed `drop` member of any impl is enough
        // to keep the type open.
        if self
            .analyzer
            .get_direct_children(unit)
            .iter()
            .any(|child| child.identifier() == "drop")
        {
            return false;
        }
        let Some(source) = self.source(unit.source()) else {
            return false;
        };
        let Some(item) = self.declaration(&source, unit) else {
            return false;
        };
        if !matches!(item.kind(), "struct_item" | "enum_item")
            || item.child_by_field_name("type_parameters").is_some()
            || outer_attributes(item).next().is_some()
        {
            return false;
        }
        let Some(body) = item.child_by_field_name("body") else {
            // A unit struct owns nothing.
            return item.kind() == "struct_item";
        };
        let mut field_types = Vec::new();
        let mut pending = vec![body];
        while let Some(node) = pending.pop() {
            match node.kind() {
                "field_declaration" => field_types.extend(node.child_by_field_name("type")),
                "ordered_field_declaration_list" => {
                    field_types.extend(named_children(node).into_iter().filter(|child| {
                        child.kind() != "attribute_item" && child.kind() != "visibility_modifier"
                    }))
                }
                "field_declaration_list" | "enum_variant_list" | "enum_variant" => {
                    pending.extend(named_children(node));
                }
                _ => {}
            }
        }
        field_types
            .into_iter()
            .all(|ty| self.type_class(&source, ty, depth).is_inert())
    }

    /// The class of the value `expression` evaluates to.
    fn expression_class(
        &self,
        source: &RustSource,
        expression: Node<'_>,
        depth: usize,
    ) -> RustValueClass {
        let key = (expression.id(), depth);
        if let Some(class) = source.expression_classes.borrow().get(&key).copied() {
            return class;
        }
        #[cfg(test)]
        {
            let evaluations = source.expression_class_evaluations.get() + 1;
            source.expression_class_evaluations.set(evaluations);
            if let Some(limit) = source.expression_class_evaluation_limit.get() {
                assert!(
                    evaluations <= limit,
                    "uncached expression proof count {evaluations} exceeded limit {limit}"
                );
            }
        }
        let class = self.expression_class_uncached(source, expression, depth);
        source.expression_classes.borrow_mut().insert(key, class);
        class
    }

    fn expression_class_uncached(
        &self,
        source: &RustSource,
        expression: Node<'_>,
        depth: usize,
    ) -> RustValueClass {
        if depth == 0 {
            incomplete_proof("depth_limit");
            return RustValueClass::Unknown;
        }
        match expression.kind() {
            "string_literal" | "raw_string_literal" => RustValueClass::Str,
            "char_literal" | "integer_literal" | "float_literal" | "boolean_literal"
            | "unit_expression" => RustValueClass::Inert,
            "parenthesized_expression" => named_children(expression)
                .first()
                .map_or(RustValueClass::Unknown, |inner| {
                    self.expression_class(source, *inner, depth - 1)
                }),
            "reference_expression" => {
                // A borrow of a place drops nothing. A borrow of any other
                // expression borrows a temporary, which a `let` extends to
                // the end of its block, so that temporary must be inert. A
                // borrow of a `String` coerces to `&str` where an argument
                // expects one.
                let Some(value) = expression.child_by_field_name("value") else {
                    return RustValueClass::Unknown;
                };
                let referent = self.expression_class(source, value, depth - 1);
                if referent == RustValueClass::String {
                    RustValueClass::Str
                } else if referent.is_inert() || is_place(source, value) {
                    RustValueClass::Inert
                } else {
                    RustValueClass::Unknown
                }
            }
            "array_expression" | "tuple_expression" => {
                if named_children(expression)
                    .into_iter()
                    .all(|element| self.expression_class(source, element, depth - 1).is_inert())
                {
                    RustValueClass::Inert
                } else {
                    RustValueClass::Unknown
                }
            }
            "binary_expression" => self.binary_class(source, expression, depth),
            "identifier" => self.binding_class(source, expression, depth),
            "scoped_identifier" => match self.workspace_definition(source, expression) {
                Some(unit) if self.workspace_type_is_inert(&unit, depth - 1) => {
                    RustValueClass::Inert
                }
                _ => RustValueClass::Unknown,
            },
            "call_expression" => self.call_class(source, expression, depth),
            _ => RustValueClass::Unknown,
        }
    }

    fn binary_class(
        &self,
        source: &RustSource,
        expression: Node<'_>,
        depth: usize,
    ) -> RustValueClass {
        let (Some(left), Some(operator), Some(right)) = (
            expression.child_by_field_name("left"),
            expression.child_by_field_name("operator"),
            expression.child_by_field_name("right"),
        ) else {
            return RustValueClass::Unknown;
        };
        match operator.kind() {
            // Comparison and logical operators always produce `bool`.
            "==" | "!=" | "<" | ">" | "<=" | ">=" | "&&" | "||" => RustValueClass::Inert,
            "+" if self.expression_class(source, left, depth - 1) == RustValueClass::String
                && self.expression_class(source, right, depth - 1) == RustValueClass::Str =>
            {
                RustValueClass::from_std(RUST_STD_STRING_ADD_STR)
            }
            _ => RustValueClass::Unknown,
        }
    }

    /// The class of the parameter or `let` binding `name` resolves to.
    fn binding_class(&self, source: &RustSource, name: Node<'_>, depth: usize) -> RustValueClass {
        let Some(identifier) = source.node_text(name) else {
            return RustValueClass::Unknown;
        };
        let Some(binding) = resolve_lexical_binding(
            Language::Rust,
            source.tree().root_node(),
            source.text(),
            name.start_byte(),
            name.end_byte(),
            identifier,
        ) else {
            // A path to a unit struct is a value too.
            return match self.workspace_definition(source, name) {
                Some(unit) if self.workspace_type_is_inert(&unit, depth - 1) => {
                    RustValueClass::Inert
                }
                _ => RustValueClass::Unknown,
            };
        };
        let (LexicalBindingResolution::Parameter(definition)
        | LexicalBindingResolution::OtherLocal(definition)) = binding;
        let Some(declaration) = source.tree().root_node().named_descendant_for_byte_range(
            definition.declaration_range.start_byte,
            definition.declaration_range.end_byte,
        ) else {
            return RustValueClass::Unknown;
        };
        let mut current = Some(declaration);
        while let Some(node) = current {
            match node.kind() {
                "parameter" => {
                    return node
                        .child_by_field_name("type")
                        .map_or(RustValueClass::Unknown, |ty| {
                            self.type_class(source, ty, depth - 1)
                        });
                }
                "let_declaration" => return self.let_class(source, node, depth - 1),
                _ if is_procedure_boundary(node.kind()) => return RustValueClass::Unknown,
                _ => current = node.parent(),
            }
        }
        RustValueClass::Unknown
    }

    /// The class of the value one `let` binds or discards.
    fn let_class(&self, source: &RustSource, binding: Node<'_>, depth: usize) -> RustValueClass {
        if let Some(ty) = binding.child_by_field_name("type") {
            return self.type_class(source, ty, depth);
        }
        // A `let ... else` diverges when the pattern is refutable, which the
        // proof does not type.
        if binding.child_by_field_name("alternative").is_some() {
            return RustValueClass::Unknown;
        }
        binding
            .child_by_field_name("value")
            .map_or(RustValueClass::Unknown, |value| {
                self.expression_class(source, value, depth)
            })
    }

    fn call_class(&self, source: &RustSource, call: Node<'_>, depth: usize) -> RustValueClass {
        if self.is_modeled_env_var_call(source, call) {
            return RustValueClass::EnvVarResult;
        }
        if let Some(class) = self.modeled_call_result_class(source, call, depth) {
            return class;
        }
        let Some(function) = call.child_by_field_name("function") else {
            return RustValueClass::Unknown;
        };
        let arity = call
            .child_by_field_name("arguments")
            .map_or(0, |arguments| named_children(arguments).len());
        let callee_name = match function.kind() {
            "field_expression" => {
                let (Some(receiver), Some(method)) = (
                    function.child_by_field_name("value"),
                    function.child_by_field_name("field"),
                ) else {
                    return RustValueClass::Unknown;
                };
                let receiver_class = self.expression_class(source, receiver, depth - 1);
                if receiver_class == RustValueClass::EnvVarResult
                    && source.node_text(method) == Some("unwrap")
                    && arity == 0
                {
                    return RustValueClass::String;
                }
                if let Some(receiver) = match receiver_class {
                    RustValueClass::Str => Some(RustStdReceiver::Str),
                    RustValueClass::String => Some(RustStdReceiver::String),
                    _ => None,
                } {
                    return source
                        .node_text(method)
                        .and_then(|method| rust_std_method_fact(receiver, method, arity))
                        .map_or(RustValueClass::Unknown, |fact| {
                            RustValueClass::from_std(fact.result)
                        });
                }
                method
            }
            "scoped_identifier" => {
                if let Some(fact) = self.prelude_type_associated_fact(source, function, arity) {
                    return RustValueClass::from_std(fact.result);
                }
                function
            }
            "identifier" => function,
            _ => return RustValueClass::Unknown,
        };
        let Some(unit) = self.workspace_definition(source, callee_name) else {
            return RustValueClass::Unknown;
        };
        if !unit.is_function() {
            return RustValueClass::Unknown;
        }
        let Some(callee_source) = self.source(unit.source()) else {
            return RustValueClass::Unknown;
        };
        let Some(callee) = self.declaration(&callee_source, &unit) else {
            return RustValueClass::Unknown;
        };
        if callee.kind() != "function_item" {
            return RustValueClass::Unknown;
        }
        match callee.child_by_field_name("return_type") {
            // A function without a written return type returns `()`.
            None => RustValueClass::Inert,
            Some(ty) => self.type_class(&callee_source, ty, depth - 1),
        }
    }

    /// The reviewed model's declaration for `std::env::var` names its outer
    /// `Result` type but leaves generic arguments untyped. Its Rust API
    /// contract fixes the success payload as `String`, which lets a following
    /// structured `Result::unwrap()` reach the existing `String::len` fact.
    fn is_modeled_env_var_call(&self, source: &RustSource, call: Node<'_>) -> bool {
        let Some(function) = call.child_by_field_name("function") else {
            return false;
        };
        if function.kind() != "scoped_identifier" {
            return false;
        }
        let Some(name) = function.child_by_field_name("name") else {
            return false;
        };
        let Some(text) = source.node_text(name) else {
            return false;
        };
        let site = ResolvedReferenceSite {
            path: text.to_owned(),
            text: text.to_owned(),
            range: node_range(name),
            focus_start_byte: name.start_byte(),
            focus_end_byte: name.end_byte(),
        };
        let Some(identity) = self.resolver.external_call_identity(
            &source.file,
            source.text(),
            source.tree(),
            &site,
            call.start_byte(),
        ) else {
            return false;
        };
        identity.owner_fqn() == "std.env"
            && identity.member() == "var"
            && call
                .child_by_field_name("arguments")
                .is_some_and(|arguments| named_children(arguments).len() == 1)
    }

    /// The reviewed fact for `Owner::function(..)` written with `arity`
    /// arguments, when `Owner` is one segment the resolver proves is a std
    /// prelude type.
    fn prelude_type_associated_fact(
        &self,
        source: &RustSource,
        path: Node<'_>,
        arity: usize,
    ) -> Option<&'static RustStdAssociatedFact> {
        if path.kind() != "scoped_identifier" {
            return None;
        }
        let owner = path.child_by_field_name("path")?;
        let function = source.node_text(path.child_by_field_name("name")?)?;
        if !matches!(owner.kind(), "identifier" | "type_identifier")
            || !RUST_STD_ASSOCIATED_FACTS
                .iter()
                .any(|fact| fact.function == function && fact.arity == arity)
        {
            return None;
        }
        let prelude = self.prelude_item(source, owner, "type")?;
        rust_std_associated_fact(&prelude, function, arity)
    }

    /// The activated model's exact callable shape for one call (#3757). The
    /// identity comes from the same structure the dispatch route proves: a
    /// receiver typed through built-in reference dereferences, or a written
    /// path rooted at an external crate. The answer is per call site; no
    /// symbol-level candidate is shared across calls with different owners or
    /// receiver shapes.
    fn modeled_call_shape(
        &self,
        source: &RustSource,
        call: Node<'_>,
        depth: usize,
    ) -> Option<RustModeledCallShape> {
        let key = (call.id(), depth);
        if let Some(shape) = source.modeled_call_shapes.borrow().get(&key) {
            return shape.clone();
        }
        #[cfg(test)]
        {
            let evaluations = source.modeled_call_shape_evaluations.get() + 1;
            source.modeled_call_shape_evaluations.set(evaluations);
            if let Some(limit) = source.modeled_call_shape_evaluation_limit.get() {
                assert!(
                    evaluations <= limit,
                    "uncached modeled call shape count {evaluations} exceeded limit {limit}"
                );
            }
        }
        let shape = self.modeled_call_shape_uncached(source, call, depth);
        source
            .modeled_call_shapes
            .borrow_mut()
            .insert(key, shape.clone());
        shape
    }

    fn modeled_call_shape_uncached(
        &self,
        source: &RustSource,
        call: Node<'_>,
        depth: usize,
    ) -> Option<RustModeledCallShape> {
        if depth == 0 {
            incomplete_proof("depth_limit");
            return None;
        }
        let function = call.child_by_field_name("function")?;
        let arity = named_children(call.child_by_field_name("arguments")?).len();
        let (owner, member, has_receiver) = match function.kind() {
            "field_expression" => {
                let receiver = function.child_by_field_name("value")?;
                let owner = self.receiver_owner_bounded(source, receiver, depth - 1)?;
                let member = source.node_text(function.child_by_field_name("field")?)?;
                (owner.key(), member.to_owned(), true)
            }
            "scoped_identifier" | "generic_function" => {
                let callee = if function.kind() == "generic_function" {
                    function.child_by_field_name("function")?
                } else {
                    function
                };
                let name = callee.child_by_field_name("name")?;
                let text = source.node_text(name)?.to_owned();
                let site = ResolvedReferenceSite {
                    path: text.clone(),
                    text,
                    range: node_range(name),
                    focus_start_byte: name.start_byte(),
                    focus_end_byte: name.end_byte(),
                };
                let identity = self.resolver.external_call_identity(
                    &source.file,
                    source.text(),
                    source.tree(),
                    &site,
                    call.start_byte(),
                )?;
                (
                    identity.owner_fqn().to_owned(),
                    identity.member().to_owned(),
                    false,
                )
            }
            _ => return None,
        };
        Some((owner, member, has_receiver, arity))
    }

    fn modeled_call_return_type(
        &self,
        source: &RustSource,
        call: Node<'_>,
        depth: usize,
    ) -> Option<TypeRef> {
        let (owner, member, has_receiver, arity) = self.modeled_call_shape(source, call, depth)?;
        let overlay = self.analyzer.semantic_model_overlay()?;
        let parameter_count = u32::try_from(arity).ok()?;
        let callable = overlay
            .callable_for_application(
                SemanticModelCallableKey::new(
                    Language::Rust.config_label(),
                    &owner,
                    &member,
                    has_receiver,
                    parameter_count,
                ),
                &SemanticModelCallApplication::positional(parameter_count),
            )
            .unique()?;
        callable.structured_signature.as_ref()?.returns.clone()
    }

    /// The owner a modeled external call's result is declared as, read from
    /// the activated model's unique callable record for the call's exact
    /// identity (#3757).
    fn modeled_call_result_owner(
        &self,
        source: &RustSource,
        call: Node<'_>,
        depth: usize,
    ) -> Option<RustReceiverOwner> {
        match self.modeled_call_return_type(source, call, depth)? {
            TypeRef::Named { name, .. } => Some(RustReceiverOwner::Path(name)),
            _ => None,
        }
    }

    /// The drop class of the model's structured return type. References,
    /// pointers, and primitive scalars cannot run user drop glue. Nominal
    /// results still need a reviewed drop fact; only the existing standard
    /// owned-memory types are known here.
    fn modeled_call_result_class(
        &self,
        source: &RustSource,
        call: Node<'_>,
        depth: usize,
    ) -> Option<RustValueClass> {
        match self.modeled_call_return_type(source, call, depth)? {
            TypeRef::ByRef { element, .. } => Some(match element.as_ref() {
                TypeRef::Named { name, .. }
                    if matches!(
                        name.as_str(),
                        "str" | "std.primitive.str" | "core.primitive.str"
                    ) =>
                {
                    RustValueClass::Str
                }
                _ => RustValueClass::Inert,
            }),
            TypeRef::Pointer { .. } => Some(RustValueClass::Inert),
            TypeRef::Named {
                name, arguments, ..
            } if arguments.is_empty() => {
                match name.as_str() {
                    "std.string.String" => Some(RustValueClass::String),
                    "std.path.Path" | "std.path.PathBuf" => Some(RustValueClass::Inert),
                    _ => {
                        // These are model type identities, not source type syntax.
                        let primitive = name
                            .strip_prefix("std.primitive.")
                            .or_else(|| name.strip_prefix("core.primitive."))
                            .unwrap_or(&name);
                        matches!(
                            primitive,
                            "bool"
                                | "char"
                                | "i8"
                                | "i16"
                                | "i32"
                                | "i64"
                                | "i128"
                                | "isize"
                                | "u8"
                                | "u16"
                                | "u32"
                                | "u64"
                                | "u128"
                                | "usize"
                                | "f16"
                                | "f32"
                                | "f64"
                                | "f128"
                        )
                        .then_some(RustValueClass::Inert)
                    }
                }
            }
            _ => None,
        }
    }

    /// The declared type of the parameter or annotated `let` that the name
    /// `receiver` resolves to.
    fn declared_binding_type<'s>(
        &self,
        source: &'s RustSource,
        receiver: Node<'s>,
    ) -> Option<Node<'s>> {
        if receiver.kind() != "identifier" {
            return None;
        }
        let identifier = source.node_text(receiver)?;
        let binding = resolve_lexical_binding(
            Language::Rust,
            source.tree().root_node(),
            source.text(),
            receiver.start_byte(),
            receiver.end_byte(),
            identifier,
        )?;
        let (LexicalBindingResolution::Parameter(definition)
        | LexicalBindingResolution::OtherLocal(definition)) = binding;
        let mut current = source.tree().root_node().named_descendant_for_byte_range(
            definition.declaration_range.start_byte,
            definition.declaration_range.end_byte,
        );
        while let Some(node) = current {
            match node.kind() {
                "parameter" | "let_declaration" => return node.child_by_field_name("type"),
                _ if is_procedure_boundary(node.kind()) => return None,
                _ => current = node.parent(),
            }
        }
        None
    }

    /// The initializer of a local binding, when the receiver is that binding.
    /// This preserves the modeled return owner of an imported associated call
    /// through an unannotated `let` instead of requiring a type annotation.
    fn binding_initializer<'s>(
        &self,
        source: &'s RustSource,
        receiver: Node<'s>,
    ) -> Option<Node<'s>> {
        if receiver.kind() != "identifier" {
            return None;
        }
        let identifier = source.node_text(receiver)?;
        let LexicalBindingResolution::OtherLocal(definition) = resolve_lexical_binding(
            Language::Rust,
            source.tree().root_node(),
            source.text(),
            receiver.start_byte(),
            receiver.end_byte(),
            identifier,
        )?
        else {
            return None;
        };
        let mut current = source.tree().root_node().named_descendant_for_byte_range(
            definition.declaration_range.start_byte,
            definition.declaration_range.end_byte,
        );
        while let Some(node) = current {
            match node.kind() {
                "let_declaration" => return node.child_by_field_name("value"),
                _ if is_procedure_boundary(node.kind()) => return None,
                _ => current = node.parent(),
            }
        }
        None
    }

    /// The canonical owner path, dot-joined, of the type a method receiver
    /// evaluates to after built-in reference dereferences, when the receiver
    /// is a `&str`, a binding or field whose nominal type the resolver proves belongs
    /// to an external crate (through the prelude, an import, or a qualified
    /// path), or the result of a modeled external call whose model declares
    /// its return type. A workspace type resolves through the workspace
    /// instead.
    fn receiver_owner(&self, source: &RustSource, receiver: Node<'_>) -> Option<RustReceiverOwner> {
        self.receiver_owner_bounded(source, receiver, PROOF_DEPTH)
    }

    fn receiver_owner_bounded(
        &self,
        source: &RustSource,
        receiver: Node<'_>,
        depth: usize,
    ) -> Option<RustReceiverOwner> {
        if self.expression_class(source, receiver, PROOF_DEPTH) == RustValueClass::Str {
            return Some(RustReceiverOwner::Std(RustStdReceiver::Str));
        }
        if receiver.kind() == "field_expression" {
            return self.field_receiver_owner(source, receiver);
        }
        if receiver.kind() == "call_expression" {
            return self.modeled_call_result_owner(source, receiver, depth);
        }
        if receiver.kind() == "macro_invocation" {
            let layout = brokk_bifrost_rust::format_args::rust_macro_runtime_layout_for_path(
                receiver.child_by_field_name("macro")?,
                source.text(),
            )?;
            let result_owner = layout.result_owner?;
            let scope = AnalyzerQueryScope::new(self.analyzer);
            let span = node_range(receiver);
            let dispatch = super::format_macro_dispatch::dispatch(
                crate::analyzer::usages::call_relations::CallDispatchLanguageRequest {
                    analyzer: self.analyzer,
                    token: scope.token(),
                    file: &source.file,
                    source: source.text(),
                    tree: source.tree(),
                    call_span: &span,
                    cancellation: self.resolver.cancellation(),
                    work: Default::default(),
                },
            )?;
            let [
                crate::analyzer::usages::call_relations::CallDispatchBoundaryKind::External {
                    external_callee_identity: Some(identity),
                    ..
                },
            ] = dispatch.boundaries.as_slice()
            else {
                return None;
            };
            return (identity.owner_fqn() == layout.owner && identity.member() == layout.member)
                .then(|| RustReceiverOwner::Path(result_owner.into()));
        }
        if depth <= 1 {
            incomplete_proof("depth_limit");
        }
        if depth > 1
            && let Some(initializer) = self.binding_initializer(source, receiver)
            && let Some(owner) = self.receiver_owner_bounded(source, initializer, depth - 1)
        {
            return Some(owner);
        }
        let ty = self.declared_binding_type(source, receiver)?;
        let (owner, _arguments) = self.nominal_type_owner(source, ty)?;
        Some(RustReceiverOwner::Path(owner))
    }

    /// A field's declared type, after the resolver has selected its actual
    /// declaration through built-in reference projection. Positional fields
    /// have a lexical source declaration instead of a display CodeUnit.
    fn field_receiver_owner(
        &self,
        source: &RustSource,
        receiver: Node<'_>,
    ) -> Option<RustReceiverOwner> {
        let outcome = self.resolve(source, receiver.child_by_field_name("field")?)?;
        if outcome.status != DefinitionLookupStatus::Resolved {
            return None;
        }
        let prove = |field_source: &RustSource, declaration: Node<'_>| {
            let ty = match declaration.kind() {
                "field_declaration" => declaration.child_by_field_name("type")?,
                _ if declaration
                    .parent()
                    .is_some_and(|parent| parent.kind() == "ordered_field_declaration_list") =>
                {
                    declaration
                }
                _ => return None,
            };
            self.nominal_type_owner(field_source, ty)
                .map(|(owner, _arguments)| RustReceiverOwner::Path(owner))
        };
        match (
            outcome.definitions.as_slice(),
            outcome.lexical_definition.as_ref(),
        ) {
            ([unit], None) if unit.is_field() => {
                let field_source = self.source(unit.source())?;
                prove(&field_source, self.declaration(&field_source, unit)?)
            }
            ([], Some(definition))
                if definition.kind == crate::analyzer::DeclarationKind::Field =>
            {
                let field_source =
                    self.source(definition.source_file.as_ref().unwrap_or(&source.file))?;
                let range = &definition.declaration_range;
                let declaration = field_source
                    .tree()
                    .root_node()
                    .named_descendant_for_byte_range(range.start_byte, range.end_byte)
                    .filter(|node| node.byte_range() == (range.start_byte..range.end_byte))?;
                prove(&field_source, declaration)
            }
            _ => None,
        }
    }

    /// Prove a nominal application from the resolver's head identity. A public
    /// declaration in a partial pack proves identity, not a closed member list.
    fn nominal_type_owner<'tree>(
        &self,
        source: &RustSource,
        mut ty: Node<'tree>,
    ) -> Option<(String, Vec<Node<'tree>>)> {
        let mut arguments = Vec::new();
        loop {
            match ty.kind() {
                "reference_type" => ty = ty.child_by_field_name("type")?,
                "generic_type" => {
                    arguments = named_children(ty.child_by_field_name("type_arguments")?)
                        .into_iter()
                        .filter(|node| node.kind() != "lifetime")
                        .collect();
                    ty = ty.child_by_field_name("type")?;
                }
                "type_identifier" | "scoped_type_identifier" => break,
                _ => return None,
            }
        }
        let outcome = self.resolve(source, ty)?;
        if !outcome.definitions.is_empty() || outcome.lexical_definition.is_some() {
            return None;
        }
        let identity = if let Some(prelude) = prelude_item_of(&outcome, "type") {
            rust_std_type_fact(&prelude)?.path.join(".")
        } else {
            let subjects = outcome
                .diagnostics
                .iter()
                .filter_map(|diagnostic| diagnostic.claim.as_ref())
                .filter(|claim| claim.kind == UnindexedClaimKind::ExternalBoundary)
                .flat_map(|claim| claim.subjects.iter())
                .collect::<Vec<_>>();
            match subjects.as_slice() {
                [subject]
                    if outcome.status == DefinitionLookupStatus::UnresolvableImportBoundary =>
                {
                    (*subject).clone()
                }
                [] if ty.kind() == "scoped_type_identifier" => {
                    // A qualified type may have no terminal reference row. Prove
                    // its root through the selected resolver instead; the model
                    // below must still publish the complete nominal identity.
                    let segments = rust_path_segments(ty)?;
                    let root = *segments.first()?;
                    let scope = AnalyzerQueryScope::new(self.analyzer);
                    if !super::external_calls::native_external_root_with_resolver(
                        self.analyzer,
                        scope.token(),
                        &source.file,
                        source.text(),
                        source.tree(),
                        root,
                        self.resolver.cancellation(),
                        |query| self.resolver.resolve(query),
                    ) {
                        return None;
                    }
                    segments
                        .iter()
                        .map(|segment| source.node_text(*segment))
                        .collect::<Option<Vec<_>>>()?
                        .join(".")
                }
                _ => return None,
            }
        };
        let overlay = self.analyzer.semantic_model_overlay()?;
        let symbol = super::crate_identity::RustOverlayCrates::new(Some(&overlay))
            .unique_symbol(&identity)?;
        if symbol.provenance.ambiguous
            || !symbol.externally_visible()
            || symbol.language != Language::Rust.config_label()
            || !matches!(
                symbol.kind,
                crate::analyzer::semantic_model::SemanticModelSymbolKind::Struct
                    | crate::analyzer::semantic_model::SemanticModelSymbolKind::Enum
                    | crate::analyzer::semantic_model::SemanticModelSymbolKind::Union
            )
        {
            return None;
        }
        let active = self.analyzer.active_semantic_models()?;
        let declarations = active.types_with_id(&symbol.id);
        if declarations.records.is_empty()
            || declarations
                .records
                .iter()
                .any(|declaration| declaration.record.type_parameters.len() != arguments.len())
        {
            incomplete_proof("external_receiver_generic_arity_mismatch");
            return None;
        }
        Some((symbol.qualified_name.clone(), arguments))
    }

    /// Whether dropping every parameter and every `let` binding of the
    /// procedure whose callable spans `callable` runs no user code.
    fn procedure_drops_are_inert(
        &self,
        file: &ProjectFile,
        source: &Arc<str>,
        callable: ByteRange<usize>,
    ) -> bool {
        let Some(rust_source) = self.source(file) else {
            return false;
        };
        if rust_source.text() != source.as_ref() {
            return false;
        }
        let Some(callable) = rust_source
            .tree()
            .root_node()
            .descendant_for_byte_range(callable.start, callable.end)
            .filter(|node| node.byte_range() == callable && is_procedure_boundary(node.kind()))
        else {
            return false;
        };
        if callable.kind() != "function_item" {
            return false;
        }
        let parameters = callable
            .child_by_field_name("parameters")
            .map(named_children)
            .unwrap_or_default();
        for parameter in parameters {
            let inert = match parameter.kind() {
                "self_parameter" => super::semantic::rust_self_parameter_is_borrowed(parameter),
                "parameter" => parameter
                    .child_by_field_name("type")
                    .is_some_and(|ty| self.type_class(&rust_source, ty, PROOF_DEPTH).is_inert()),
                "attribute_item" => true,
                _ => false,
            };
            if !inert {
                return false;
            }
        }
        let Some(body) = callable.child_by_field_name("body") else {
            return true;
        };
        let mut pending = vec![body];
        while let Some(node) = pending.pop() {
            if node != body && is_procedure_boundary(node.kind()) {
                continue;
            }
            if node.kind() == "let_declaration"
                && !self.let_class(&rust_source, node, PROOF_DEPTH).is_inert()
            {
                return false;
            }
            pending.extend(named_children(node));
        }
        true
    }
}

/// Prove the native B4/B5 obligation for one resolved Rust callable and one
/// result port. The caller owns dispatch completeness; this function answers
/// only the selected declaration's static signature and attributes.
pub fn rust_native_result_obligation(
    analyzer: &dyn IAnalyzer,
    target: &CodeUnit,
    result_ordinal: u32,
) -> RustNativeObligationProof {
    let Some(proof) = RustTypeProof::new(analyzer) else {
        return RustNativeObligationProof::Open("native_rust_analyzer");
    };
    proof.native_obligation_for_target(target, result_ordinal)
}

/// Whether `call` is the resolver-proven prelude `drop` wrapper. The wrapper
/// itself returns unit and contributes no discarded-result obligation, while
/// its argument call remains a separate result-use observation.
pub fn rust_call_is_standard_drop(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    range: Range,
) -> bool {
    let Some(proof) = RustTypeProof::new(analyzer) else {
        return false;
    };
    let Some(rust_source) = proof.source(file) else {
        return false;
    };
    if rust_source.text() != source {
        return false;
    }
    let Some(call) = rust_source
        .tree()
        .root_node()
        .named_descendant_for_byte_range(range.start_byte, range.end_byte)
        .filter(|node| {
            node.kind() == "call_expression"
                && node.byte_range() == (range.start_byte..range.end_byte)
        })
    else {
        return false;
    };
    let Some(function) = call.child_by_field_name("function") else {
        return false;
    };
    function.kind() == "identifier"
        && rust_source.node_text(function) == Some("drop")
        && proof
            .prelude_item(&rust_source, function, "value")
            .as_deref()
            == Some("drop")
}

/// Whether dropping every parameter and every `let` binding of the Rust
/// procedure whose callable spans `callable` in `source` runs no user code.
pub(crate) fn procedure_drops_run_no_user_code(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &Arc<str>,
    callable: ByteRange<usize>,
) -> bool {
    RustTypeProof::new(analyzer)
        .is_some_and(|proof| proof.procedure_drops_are_inert(file, source, callable))
}

/// The owner a method receiver's type is published under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RustReceiverOwner {
    /// A receiver type the reviewed std facts describe.
    Std(RustStdReceiver),
    /// The dot-joined canonical path of a std prelude type or a
    /// `use`-imported external type.
    Path(String),
}

impl RustReceiverOwner {
    pub(crate) fn key(&self) -> String {
        match self {
            Self::Std(receiver) => receiver.owner_path().join("."),
            Self::Path(path) => path.clone(),
        }
    }
}

/// The owner of the receiver type of the Rust method call whose method name
/// spans `method` in `source`, with the call's written argument count. See
/// [`RustTypeProof::receiver_owner`].
pub(crate) fn rust_method_receiver_owner(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    method: ByteRange<usize>,
) -> Option<(RustReceiverOwner, usize)> {
    completed_proof(None, || {
        let Some(proof) = RustTypeProof::new(analyzer) else {
            incomplete_proof("analyzer_unavailable");
            return None;
        };
        rust_method_receiver_owner_with_proof(&proof, file, source, method)
    })
    .into_value()
}

pub(crate) fn rust_method_receiver_owner_with_operation<'analyzer, 'factory, 'selection>(
    analyzer: &'analyzer dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    method: ByteRange<usize>,
    factory: &'factory super::native_points::RustDefinitionOperationFactory<'analyzer>,
    operation: &mut crate::analyzer::store::resolution_operation::SelectedResolutionOperation<
        'analyzer,
        'selection,
    >,
    cancellation: Option<&crate::CancellationToken>,
) -> Option<(RustReceiverOwner, usize)> {
    rust_method_receiver_owner_attempt_with_operation(
        analyzer,
        file,
        source,
        method,
        factory,
        operation,
        cancellation,
    )
    .into_value()
}

pub(crate) fn rust_method_receiver_owner_attempt_with_operation<'analyzer, 'factory, 'selection>(
    analyzer: &'analyzer dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    method: ByteRange<usize>,
    factory: &'factory super::native_points::RustDefinitionOperationFactory<'analyzer>,
    operation: &mut crate::analyzer::store::resolution_operation::SelectedResolutionOperation<
        'analyzer,
        'selection,
    >,
    cancellation: Option<&crate::CancellationToken>,
) -> RustProofAttempt<(RustReceiverOwner, usize)> {
    completed_proof(cancellation, || {
        let Some(rust) = resolve_analyzer::<RustAnalyzer>(analyzer) else {
            incomplete_proof("analyzer_unavailable");
            return None;
        };
        let proof = RustTypeProof {
            analyzer,
            rust,
            resolver: SelectedRustTypeProofResolver {
                analyzer,
                factory,
                operation: RefCell::new(operation),
                cancellation,
            },
        };
        rust_method_receiver_owner_with_proof(&proof, file, source, method)
    })
}

/// Resolve a declared type reached by the receiver-facts traversal with the
/// same nominal proof used by the direct receiver route.
#[allow(clippy::too_many_arguments)]
pub(crate) fn rust_nominal_receiver_owner_with_operation<'analyzer>(
    analyzer: &'analyzer dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    ty: Node<'_>,
    factory: Option<&super::native_points::RustDefinitionOperationFactory<'analyzer>>,
    operation: Option<
        &mut crate::analyzer::store::resolution_operation::SelectedResolutionOperation<
            'analyzer,
            '_,
        >,
    >,
    cancellation: Option<&crate::CancellationToken>,
) -> Option<String> {
    completed_proof(cancellation, || {
        let prove = |proof: &RustTypeProof<'_, _>| {
            let rust_source = proof.source(file)?;
            if rust_source.text() != source {
                incomplete_proof("source_mismatch");
                return None;
            }
            proof
                .nominal_type_owner(&rust_source, ty)
                .map(|(owner, _arguments)| owner)
        };
        match operation {
            Some(operation) => {
                let proof = RustTypeProof {
                    analyzer,
                    rust: resolve_analyzer::<RustAnalyzer>(analyzer)?,
                    resolver: SelectedRustTypeProofResolver {
                        analyzer,
                        factory: factory.expect("a selected Rust operation has its factory"),
                        operation: RefCell::new(operation),
                        cancellation,
                    },
                };
                prove(&proof)
            }
            None => {
                let proof = RustTypeProof::new(analyzer)?;
                // The factory resolver owns its operation when no selection is supplied.
                let rust_source = proof.source(file)?;
                if rust_source.text() != source {
                    incomplete_proof("source_mismatch");
                    return None;
                }
                proof
                    .nominal_type_owner(&rust_source, ty)
                    .map(|(owner, _arguments)| owner)
            }
        }
    })
    .into_value()
}

fn rust_method_receiver_owner_with_proof<R: RustTypeProofResolver>(
    proof: &RustTypeProof<'_, R>,
    file: &ProjectFile,
    source: &str,
    method: ByteRange<usize>,
) -> Option<(RustReceiverOwner, usize)> {
    let rust_source = proof.source(file)?;
    if rust_source.text() != source {
        incomplete_proof("source_mismatch");
        return None;
    }
    let name = rust_source
        .tree()
        .root_node()
        .named_descendant_for_byte_range(method.start, method.end)
        .filter(|node| node.byte_range() == method)?;
    let function = name.parent().filter(|parent| {
        parent.kind() == "field_expression" && parent.child_by_field_name("field") == Some(name)
    })?;
    let call = function.parent().filter(|parent| {
        parent.kind() == "call_expression"
            && parent.child_by_field_name("function") == Some(function)
    })?;
    let arity = named_children(call.child_by_field_name("arguments")?).len();
    let owner = proof.receiver_owner(&rust_source, function.child_by_field_name("value")?)?;
    Some((owner, arity))
}

/// The `std` or `core` prelude item `outcome` proves its reference names in
/// `namespace` (`"type"` or `"value"`): no workspace declaration, lexical
/// binding, or `use` route, and exactly one prelude reason.
pub(crate) fn prelude_item_of(
    outcome: &DefinitionLookupOutcome,
    namespace: &str,
) -> Option<String> {
    prelude_item_identity_of(outcome, namespace).map(|(_, name)| name)
}

/// The selected prelude crate and item, preserving core/std route authority.
pub(crate) fn prelude_item_identity_of(
    outcome: &DefinitionLookupOutcome,
    namespace: &str,
) -> Option<(String, String)> {
    if outcome.status != DefinitionLookupStatus::UnresolvableImportBoundary
        || !outcome.definitions.is_empty()
        || outcome.lexical_definition.is_some()
        || outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.claim.is_some())
    {
        return None;
    }
    let mut prelude = outcome
        .diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.kind == "rust_prelude_item");
    let reason = prelude.next()?;
    if prelude.next().is_some() {
        return None;
    }
    let evidence: serde_json::Value =
        serde_json::from_str(&reason.message).expect("a Rust prelude reason carries JSON evidence");
    let standard = matches!(evidence["crate"].as_str(), Some("std" | "core"));
    (standard && evidence["namespace"].as_str() == Some(namespace))
        .then(|| {
            Some((
                evidence["crate"].as_str()?.to_owned(),
                evidence["name"].as_str()?.to_owned(),
            ))
        })
        .flatten()
}

/// What one reviewed std operation transfers at its call (#3757).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RustStdBuiltinTransfer {
    /// The receiver's value reaches the normal result: `str::to_owned`,
    /// `str::len`.
    ReceiverToResult,
    /// The one argument's value reaches the normal result: `Ok(x)`,
    /// `Err(x)`, `Some(x)`.
    ArgumentToResult,
    /// The normal result is fresh and no input reaches it: `String::new()`.
    FreshResult,
}

/// One call of a reviewed std operation of the in-code fact table, and what
/// it transfers (#3757). These are Bifrost-authored language-library facts,
/// not reviewed pack summaries, so they model the call at the derived tier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustStdBuiltinCall {
    /// The operation's canonical dot-joined std path, such as
    /// `std.primitive.str.to_owned`.
    pub operation: String,
    pub transfer: RustStdBuiltinTransfer,
}

impl<'a, R: RustTypeProofResolver> RustTypeProof<'a, R> {
    /// The reviewed std operation `call` invokes, when its identity is
    /// proven: the receiver is a `&str` by structure and the resolver finds
    /// no workspace candidate for the method (a same-named workspace trait
    /// method on `str` would make the call ambiguous with the std method,
    /// rustc E0034), or the resolver proves the callee or its owner is the
    /// `std` or `core` prelude item.
    ///
    /// Each branch first checks the written name and arity against the
    /// reviewed fact tables, which are keyed by them, and resolves names
    /// only for a call some fact could describe: the resolution is the
    /// expensive part, and most calls name no reviewed operation.
    fn builtin_call(&self, source: &RustSource, call: Node<'_>) -> Option<RustStdBuiltinCall> {
        let function = call.child_by_field_name("function")?;
        let arity = named_children(call.child_by_field_name("arguments")?).len();
        match function.kind() {
            "field_expression" => {
                let receiver = function.child_by_field_name("value")?;
                let method = function.child_by_field_name("field")?;
                let name = source.node_text(method)?;
                if !RUST_STD_METHOD_FACTS
                    .iter()
                    .any(|fact| fact.method == name && fact.arity == arity)
                {
                    return None;
                }
                let receiver = match self.expression_class(source, receiver, PROOF_DEPTH) {
                    RustValueClass::Str => RustStdReceiver::Str,
                    RustValueClass::String => RustStdReceiver::String,
                    _ => return None,
                };
                let fact = rust_std_method_fact(receiver, name, arity)?;
                let outcome = self.resolve(source, method)?;
                if !outcome.definitions.is_empty() || outcome.lexical_definition.is_some() {
                    return None;
                }
                Some(RustStdBuiltinCall {
                    operation: format!("{}.{}", fact.receiver.owner_path().join("."), fact.method),
                    transfer: RustStdBuiltinTransfer::ReceiverToResult,
                })
            }
            "identifier" => {
                // A prelude reason names the spelling it resolved, so the
                // written name is the prelude name the fact must match.
                rust_std_constructor_fact(source.node_text(function)?)?;
                let name = self.prelude_item(source, function, "value")?;
                let fact = rust_std_constructor_fact(&name)?;
                (fact.arity == arity).then(|| RustStdBuiltinCall {
                    operation: format!(
                        "{}.{}",
                        rust_std_type_fact(fact.constructs)
                            .expect("a reviewed constructor names a reviewed std type")
                            .path
                            .join("."),
                        fact.name
                    ),
                    transfer: RustStdBuiltinTransfer::ArgumentToResult,
                })
            }
            "scoped_identifier" => {
                let fact = self.prelude_type_associated_fact(source, function, arity)?;
                Some(RustStdBuiltinCall {
                    operation: format!(
                        "{}.{}",
                        rust_std_type_fact(fact.owner)?.path.join("."),
                        fact.function
                    ),
                    transfer: RustStdBuiltinTransfer::FreshResult,
                })
            }
            _ => None,
        }
    }
}

/// The reviewed std operation the Rust call spanning `call` in `source`
/// invokes, if its identity is proven. See [`RustTypeProof::builtin_call`].
pub(crate) fn rust_std_builtin_call(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &Arc<str>,
    call: ByteRange<usize>,
) -> Option<RustStdBuiltinCall> {
    let proof = RustTypeProof::new(analyzer)?;
    let rust_source = proof.source(file)?;
    if rust_source.text() != source.as_ref() {
        return None;
    }
    let node = rust_source
        .tree()
        .root_node()
        .named_descendant_for_byte_range(call.start, call.end)
        .filter(|node| node.byte_range() == call && node.kind() == "call_expression")?;
    proof.builtin_call(&rust_source, node)
}

/// Identity conversions proven from structured declared error types.
/// Boxing needs source-side trait bounds and is not discharged here.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RustResidualError {
    Unit,
    Primitive(String),
    ReferenceStr(bool),
    Declaration(CodeUnit),
}

impl<R: RustTypeProofResolver> RustTypeProof<'_, R> {
    // This proof recursion has a fixed depth cap, shared with other std proofs.
    fn residual_error_type(
        &self,
        source: &RustSource,
        ty: Node<'_>,
        depth: usize,
    ) -> Option<RustResidualError> {
        if depth == 0 {
            return None;
        }
        match ty.kind() {
            "unit_type" => Some(RustResidualError::Unit),
            "primitive_type" => Some(RustResidualError::Primitive(
                source.node_text(ty)?.to_owned(),
            )),
            "reference_type" => {
                let referent = ty.child_by_field_name("type")?;
                (referent.kind() == "primitive_type" && source.node_text(referent) == Some("str"))
                    .then(|| {
                        RustResidualError::ReferenceStr(
                            named_children(ty)
                                .iter()
                                .any(|child| child.kind() == "mutable_specifier"),
                        )
                    })
            }
            "type_identifier" | "scoped_type_identifier" | "generic_type" => {
                let name = if ty.kind() == "generic_type" {
                    ty.child_by_field_name("type")?
                } else {
                    ty
                };
                let unit = self.workspace_definition(source, name)?;
                let alias_source = self.source(unit.source())?;
                let declaration = self.declaration(&alias_source, &unit)?;
                if declaration.kind() == "type_item" {
                    self.residual_error_type(
                        &alias_source,
                        declaration.child_by_field_name("type")?,
                        depth - 1,
                    )
                } else if matches!(declaration.kind(), "struct_item" | "enum_item")
                    && declaration.child_by_field_name("type_parameters").is_none()
                {
                    Some(RustResidualError::Declaration(unit))
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    fn result_error_type(
        &self,
        source: &RustSource,
        ty: Node<'_>,
        depth: usize,
    ) -> Option<RustResidualError> {
        if depth == 0
            || !matches!(
                ty.kind(),
                "generic_type" | "type_identifier" | "scoped_type_identifier"
            )
        {
            return None;
        }
        let name = if ty.kind() == "generic_type" {
            ty.child_by_field_name("type")?
        } else {
            ty
        };
        if self.standard_result_type(source, name) {
            let arguments = named_children(ty.child_by_field_name("type_arguments")?);
            let [_, error] = arguments.as_slice() else {
                return None;
            };
            return self.residual_error_type(source, *error, depth - 1);
        }
        let unit = self.workspace_definition(source, name)?;
        let alias_source = self.source(unit.source())?;
        let declaration = self.declaration(&alias_source, &unit)?;
        (declaration.kind() == "type_item").then_some(())?;
        self.result_error_type(
            &alias_source,
            declaration.child_by_field_name("type")?,
            depth - 1,
        )
    }

    fn operand_error_type(
        &self,
        source: &RustSource,
        operand: Node<'_>,
        depth: usize,
    ) -> Option<RustResidualError> {
        if depth == 0 {
            return None;
        }
        match operand.kind() {
            "identifier" => {
                if let Some(ty) = self.declared_binding_type(source, operand) {
                    self.result_error_type(source, ty, depth - 1)
                } else {
                    self.operand_error_type(
                        source,
                        self.binding_initializer(source, operand)?,
                        depth - 1,
                    )
                }
            }
            "parenthesized_expression" => {
                self.operand_error_type(source, *named_children(operand).first()?, depth - 1)
            }
            "call_expression" => {
                let function = operand.child_by_field_name("function")?;
                if function.kind() == "identifier"
                    && self.prelude_item(source, function, "value").as_deref() == Some("Err")
                {
                    let arguments = named_children(operand.child_by_field_name("arguments")?);
                    let [argument] = arguments.as_slice() else {
                        return None;
                    };
                    return (argument.kind() == "unit_expression")
                        .then_some(RustResidualError::Unit);
                }
                let function = call_function_target(function);
                let name = match function.kind() {
                    "field_expression" => function.child_by_field_name("field")?,
                    "identifier" | "scoped_identifier" => function,
                    _ => return None,
                };
                let unit = self.workspace_definition(source, name)?;
                let callee_source = self.source(unit.source())?;
                let declaration = self.declaration(&callee_source, &unit)?;
                self.result_error_type(
                    &callee_source,
                    declaration.child_by_field_name("return_type")?,
                    depth - 1,
                )
            }
            _ => None,
        }
    }
}

pub(crate) fn residual_conversion_runs_no_user_code(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    exact_source: &Arc<str>,
    question: ByteRange<usize>,
) -> bool {
    let Some(proof) = RustTypeProof::new(analyzer) else {
        return false;
    };
    let Some(source) = proof.source(file) else {
        return false;
    };
    if source.text() != exact_source.as_ref() {
        return false;
    }
    let Some(node) = source
        .tree()
        .root_node()
        .named_descendant_for_byte_range(question.start, question.end)
        .filter(|node| node.byte_range() == question && node.kind() == "try_expression")
    else {
        return false;
    };
    let mut callable = node.parent();
    while let Some(parent) = callable {
        if is_procedure_boundary(parent.kind()) {
            break;
        }
        callable = parent.parent();
    }
    let Some(return_type) = callable.and_then(|node| node.child_by_field_name("return_type"))
    else {
        return false;
    };
    let Some(error) = proof.result_error_type(&source, return_type, PROOF_DEPTH) else {
        return false;
    };
    named_children(node)
        .first()
        .and_then(|operand| proof.operand_error_type(&source, *operand, PROOF_DEPTH))
        .is_some_and(|operand_error| operand_error == error)
}

/// A callable whose body is a separate procedure.
/// Whether `expression` is a place rooted at `self` or a local binding, so
/// borrowing it creates no temporary.
fn is_place(source: &RustSource, expression: Node<'_>) -> bool {
    let mut current = expression;
    loop {
        match current.kind() {
            "self" => return true,
            "identifier" => {
                return source.node_text(current).is_some_and(|identifier| {
                    resolve_lexical_binding(
                        Language::Rust,
                        source.tree().root_node(),
                        source.text(),
                        current.start_byte(),
                        current.end_byte(),
                        identifier,
                    )
                    .is_some()
                });
            }
            "field_expression" => match current.child_by_field_name("value") {
                Some(value) => current = value,
                None => return false,
            },
            _ => return false,
        }
    }
}

fn is_procedure_boundary(kind: &str) -> bool {
    matches!(
        kind,
        "function_item" | "closure_expression" | "async_block" | "gen_block"
    )
}

fn node_range(node: Node<'_>) -> Range {
    Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: node.start_position().row + 1,
        end_line: node.end_position().row + 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_receiver_completion_preserves_values_and_unwinds() {
        for status in [
            DefinitionLookupStatus::Unavailable,
            DefinitionLookupStatus::Cancelled,
        ] {
            let attempt = completed_proof(None, || {
                let nested = completed_proof(None, || {
                    observe_proof_resolution(&BoundedResolution::Complete {
                        value: DefinitionLookupOutcome {
                            status,
                            modeled_definitions: Vec::new(),
                            reference: None,
                            definitions: Vec::new(),
                            lexical_definition: None,
                            diagnostics: Vec::new(),
                        },
                        work: Default::default(),
                    });
                    Some(7)
                });
                assert_eq!(nested.into_value(), Some(7));
                Some(9)
            });
            assert!(matches!(
                attempt,
                RustProofAttempt::Incomplete { value: Some(9), .. }
            ));
        }
        let panic = std::panic::catch_unwind(|| {
            completed_proof::<()>(None, || {
                incomplete_proof("cancelled");
                panic!("proof interrupted");
            })
        });
        assert!(panic.is_err());
        assert!(matches!(
            completed_proof::<()>(None, || None),
            RustProofAttempt::Complete(None)
        ));
    }

    use crate::analyzer::Language;
    use crate::analyzer::semantic_model::{
        CatalogCoordinate, CompilerOptions, SemanticModelActivationControl,
        SemanticModelActivationEvidence, SemanticModelActivationRequest,
        SemanticModelControlAction, SemanticModelControlScope, SemanticModelPackSelector,
        SemanticModelRuntimeLimits, SemanticModelRuntimeOutcome, SemanticPackCatalog,
        SessionPackSource, SessionPackSourceKind, SourceFormat, acquire_active_semantic_models,
        compile_source,
    };
    use crate::test_support::AnalyzerFixture;
    use brokk_bifrost_test_macros::hardwon;

    #[hardwon("#4626: same-file type-proof leaves reused query-local macro frontier state")]
    #[test]
    fn type_proof_reuses_overlay_inputs_but_opens_fresh_operations_per_leaf() {
        let source = r#"
macro_rules! checkpointed {
    ($(($name:ident, $value:path),)*) => { $(fn $name() -> Known { $value })* };
}
enum Known { First, Second }
struct Container;
impl Container {
    checkpointed!((first, Known::First), (second, Known::Second),);
}
pub struct Item;
pub fn run() { let first = Item; let second = Item; }
"#;
        let fixture = AnalyzerFixture::new_for_language(Language::Rust, &[("lib.rs", source)]);
        let analyzer = fixture.analyzer.analyzer();
        let file = ProjectFile::new(fixture.project_root(), "lib.rs");
        let proof = RustTypeProof::new(analyzer).expect("Rust type proof");
        let rust_source = proof.source(&file).expect("prepared Rust source");
        let mut pending = vec![rust_source.tree().root_node()];
        let mut references = Vec::new();
        while let Some(node) = pending.pop() {
            if matches!(node.kind(), "identifier" | "type_identifier")
                && rust_source.node_text(node) == Some("Item")
                && node
                    .parent()
                    .is_some_and(|parent| parent.kind() != "struct_item")
            {
                references.push(node);
            }
            pending.extend(named_children(node));
        }
        references.reverse();
        assert_eq!(references.len(), 2);

        super::super::native_points::reset_rust_definition_operation_open_count_for_test();
        super::super::native_points::reset_rust_definition_overlay_preparation_count_for_test();
        let proof_outcomes = references
            .iter()
            .copied()
            .map(|node| {
                proof
                    .resolve(&rust_source, node)
                    .expect("complete proof lookup")
            })
            .collect::<Vec<_>>();
        assert_eq!(
            super::super::native_points::rust_definition_overlay_preparation_count_for_test(),
            1,
            "one type proof prepares its selected overlay inputs once across leaf lookups"
        );
        assert_eq!(
            super::super::native_points::rust_definition_operation_open_count_for_test(),
            2,
            "each independent type-proof leaf gets its own selected operation"
        );

        super::super::native_points::reset_rust_definition_operation_open_count_for_test();
        super::super::native_points::reset_rust_definition_overlay_preparation_count_for_test();
        let direct_outcomes = references
            .iter()
            .copied()
            .map(|node| {
                let text = rust_source
                    .node_text(node)
                    .expect("reference name")
                    .to_owned();
                let site = ResolvedReferenceSite {
                    path: text.clone(),
                    text,
                    range: node_range(node),
                    focus_start_byte: node.start_byte(),
                    focus_end_byte: node.end_byte(),
                };
                match super::super::native_points::resolve_rust_definition_bounded(
                    BoundedReceiverQuery {
                        analyzer,
                        file: &file,
                        source: rust_source.text(),
                        tree: Some(rust_source.tree()),
                        site: &site,
                        budget: INTERACTIVE_TYPE_LOOKUP_BUDGET,
                        cancellation: None,
                    },
                ) {
                    BoundedResolution::Complete { value, .. } => value,
                    BoundedResolution::Exceeded { .. } | BoundedResolution::Cancelled { .. } => {
                        panic!("direct definition lookup did not complete")
                    }
                }
            })
            .collect::<Vec<_>>();
        assert_eq!(
            super::super::native_points::rust_definition_overlay_preparation_count_for_test(),
            2,
            "independent leaf lookups prepare the overlay inputs independently"
        );
        assert_eq!(
            super::super::native_points::rust_definition_operation_open_count_for_test(),
            2,
            "independent leaf queries each open their own selected operation"
        );
        for (proof, direct) in proof_outcomes.iter().zip(direct_outcomes) {
            assert_eq!(proof.status, direct.status);
            assert_eq!(
                proof
                    .definitions
                    .iter()
                    .map(CodeUnit::declaration_id)
                    .collect::<Vec<_>>(),
                direct
                    .definitions
                    .iter()
                    .map(CodeUnit::declaration_id)
                    .collect::<Vec<_>>(),
            );
        }
    }

    #[test]
    fn imported_external_constructor_proves_modeled_receiver_owner() {
        let source = "use std::process::Command;\n\nfn chained() {\n    Command::new(\"sh\").arg(\"-c\");\n}\n\nfn bound() {\n    let mut command = Command::new(\"sh\");\n    command.arg(\"-c\");\n}\n\nfn typed() {\n    let mut command: Command = Command::new(\"sh\");\n    command.arg(\"-c\");\n}\n\nfn direct() {\n    Command::new(\"sh\");\n}\n";
        let fixture = AnalyzerFixture::new_for_language(Language::Rust, &[("lib.rs", source)]);
        activate_imported_constructor_model(&fixture);

        let file = ProjectFile::new(fixture.project_root(), "lib.rs");
        let constructor_start = source.find("new(").expect("fixture contains new");
        let rust_source = RustTypeProof::new(fixture.analyzer.analyzer())
            .expect("Rust type proof")
            .source(&file)
            .expect("prepared Rust source");
        let site = ResolvedReferenceSite {
            path: "new".to_owned(),
            text: "new".to_owned(),
            range: Range {
                start_byte: constructor_start,
                end_byte: constructor_start + 3,
                start_line: 0,
                end_line: 0,
            },
            focus_start_byte: constructor_start,
            focus_end_byte: constructor_start + 3,
        };
        let scope = AnalyzerQueryScope::new(fixture.analyzer.analyzer());
        let (_, identity) =
            crate::analyzer::rust::external_calls::resolve_exact_rust_external_call_with_operation(
                fixture.analyzer.analyzer(),
                scope.token(),
                &file,
                rust_source.text(),
                rust_source.tree(),
                &site,
                || None,
                None,
                None,
                None,
            )
            .expect("imported constructor resolves through the activated model");
        assert_eq!(identity.owner_fqn(), "std.process.Command");
        assert_eq!(identity.member(), "new");

        let owners = source
            .match_indices("arg(")
            .map(|(method_start, _)| {
                rust_method_receiver_owner(
                    fixture.analyzer.analyzer(),
                    &file,
                    source,
                    method_start..method_start + 3,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            owners,
            vec![
                Some((RustReceiverOwner::Path("std.process.Command".to_owned()), 1)),
                Some((RustReceiverOwner::Path("std.process.Command".to_owned()), 1)),
                Some((RustReceiverOwner::Path("std.process.Command".to_owned()), 1)),
            ]
        );

        let method_start = source.find("arg(").expect("fixture contains arg");
        let rust_source = RustTypeProof::new(fixture.analyzer.analyzer())
            .expect("Rust type proof")
            .source(&file)
            .expect("prepared Rust source");
        let file_evidence = ExternalCalleeFileEvidence::default();
        let external_site = ExternalCalleeSite {
            source: rust_source.text(),
            tree: rust_source.tree(),
            callee_start_byte: method_start,
            file_evidence: &file_evidence,
        };
        let imported = super::super::expand_rust_imported_external_callee(
            fixture.analyzer.analyzer(),
            &file,
            "",
            Some(&external_site),
        )
        .expect("imported receiver method reaches the external proof fallback");
        let identity = imported
            .external_callee_identity
            .as_ref()
            .expect("receiver fallback publishes the selected identity");
        assert_eq!(identity.owner_fqn(), "std.process.Command");
        assert_eq!(identity.member(), "arg");
    }

    #[test]
    fn prelude_and_std_root_constructors_use_pack_identity_when_unreviewed() {
        let source = "fn run(size: usize) {\n    Vec::<u8>::with_capacity(size);\n    let typed: Vec<u8> = Vec::with_capacity(size);\n    std::vec::Vec::with_capacity(size);\n}\n";
        let fixture = AnalyzerFixture::new_for_language(Language::Rust, &[("lib.rs", source)]);
        activate_imported_constructor_model(&fixture);
        let analyzer = fixture.analyzer.analyzer();
        let file = ProjectFile::new(fixture.project_root(), "lib.rs");
        let identities = source
            .match_indices("with_capacity")
            .map(|(start, _)| {
                let proof = RustTypeProof::new(analyzer).expect("Rust type proof");
                let rust_source = proof.source(&file).expect("prepared Rust source");
                let site = ResolvedReferenceSite {
                    path: "with_capacity".to_owned(),
                    text: "with_capacity".to_owned(),
                    range: Range {
                        start_byte: start,
                        end_byte: start + "with_capacity".len(),
                        start_line: 0,
                        end_line: 0,
                    },
                    focus_start_byte: start,
                    focus_end_byte: start + "with_capacity".len(),
                };
                let scope = AnalyzerQueryScope::new(analyzer);
                crate::analyzer::rust::external_calls::resolve_exact_rust_external_call_with_operation(
                    analyzer,
                    scope.token(),
                    &file,
                    rust_source.text(),
                    rust_source.tree(),
                    &site,
                    || None,
                    None,
                    None,
                    None,
                )
                .map(|(_, identity)| {
                    (
                        identity.owner_fqn().to_owned(),
                        identity.member().to_owned(),
                    )
                })
            })
            .collect::<Vec<_>>();
        assert_eq!(
            identities,
            vec![
                Some(("std.vec.Vec".to_owned(), "with_capacity".to_owned())),
                Some(("std.vec.Vec".to_owned(), "with_capacity".to_owned())),
                Some(("std.vec.Vec".to_owned(), "with_capacity".to_owned())),
            ]
        );
    }

    #[test]
    fn modeled_path_constructor_proves_join_receiver_owner() {
        let source = "use std::path::Path;\n\nfn run(value: &str) {\n    Path::new(\"/srv\").join(value);\n}\n";
        let fixture = AnalyzerFixture::new_for_language(Language::Rust, &[("lib.rs", source)]);
        let pack = serde_json::json!({
            "schema_version": 2,
            "pack_id": "fixture.rust-path-owner",
            "version": "1.0.0",
            "producer": { "name": "rust-type-proof-test", "version": "1.0.0" },
            "language": "rust",
            "ecosystem": "cargo",
            "compatibility": { "bifrost": "*", "toolchains": [] },
            "provenance": { "source": "unit test" },
            "license": "NOASSERTION",
            "completeness": "complete",
            "safety": { "generated_code_only": false, "review_required": false },
            "shards": [{
                "id": "declarations.rust-path-owner",
                "activation": [{ "targets": [], "configurations": [] }],
                "payload": {
                    "kind": "declaration_facts",
                    "types": [
                        rust_type("std", "module"),
                        rust_type("std.path", "module"),
                        rust_type("std.path.Path", "struct"),
                        rust_type("std.path.PathBuf", "struct")
                    ],
                    "members": [rust_path_constructor(), rust_path_method()],
                    "relations": []
                }
            }]
        });
        activate_model_pack(&fixture, pack, "fixture.rust-path-owner", "std");
        let analyzer = fixture.analyzer.analyzer();
        let file = ProjectFile::new(fixture.project_root(), "lib.rs");
        let method_start = source.find("join").expect("fixture contains join");
        let (owner, arity) = rust_method_receiver_owner(
            analyzer,
            &file,
            source,
            method_start..method_start + "join".len(),
        )
        .expect("modeled Path::new return proves the join receiver owner");
        assert_eq!(owner.key(), "std.path.Path");
        assert_eq!(arity, 1);
    }

    #[test]
    fn modeled_path_return_proves_local_drop_glue_is_inert() {
        let source = Arc::<str>::from(
            "use std::path::Path;\n\nfn run(value: &str) {\n    let joined = Path::new(\"/srv\").join(value);\n    std::fs::read(joined);\n}\n",
        );
        let fixture = AnalyzerFixture::new_for_language(Language::Rust, &[("lib.rs", &source)]);
        let pack = serde_json::json!({
            "schema_version": 2,
            "pack_id": "fixture.rust-path-owner",
            "version": "1.0.0",
            "producer": { "name": "rust-type-proof-test", "version": "1.0.0" },
            "language": "rust",
            "ecosystem": "cargo",
            "compatibility": { "bifrost": "*", "toolchains": [] },
            "provenance": { "source": "unit test" },
            "license": "NOASSERTION",
            "completeness": "complete",
            "safety": { "generated_code_only": false, "review_required": false },
            "shards": [{
                "id": "declarations.rust-path-owner",
                "activation": [{ "targets": [], "configurations": [] }],
                "payload": {
                    "kind": "declaration_facts",
                    "types": [
                        rust_type("std", "module"),
                        rust_type("std.path", "module"),
                        rust_type("std.path.Path", "struct"),
                        rust_type("std.path.PathBuf", "struct")
                    ],
                    "members": [rust_path_constructor(), rust_path_method()],
                    "relations": []
                }
            }]
        });
        activate_model_pack(&fixture, pack, "fixture.rust-path-owner", "std");
        let file = ProjectFile::new(fixture.project_root(), "lib.rs");
        let callable = source.find("fn run").expect("fixture function")..source.trim_end().len();
        assert!(procedure_drops_run_no_user_code(
            fixture.analyzer.analyzer(),
            &file,
            &source,
            callable,
        ));
    }

    #[test]
    fn modeled_builder_chain_proof_growth() {
        let length = PROOF_DEPTH + 4;
        let source = format!(
            "use std::path::Path;\nfn chain_{length}() {{ let _ = Path::new(\"root\"){}; }}\n",
            ".join(\"part\")".repeat(length)
        );
        let fixture = AnalyzerFixture::new_for_language(Language::Rust, &[("lib.rs", &source)]);
        activate_path_chain_model(&fixture);
        let file = ProjectFile::new(fixture.project_root(), "lib.rs");
        let proof = RustTypeProof::new(fixture.analyzer.analyzer()).expect("Rust type proof");
        let rust_source = proof.source(&file).expect("prepared Rust source");
        let mut pending = vec![rust_source.tree().root_node()];
        let mut functions = Vec::new();
        while let Some(node) = pending.pop() {
            if node.kind() == "function_item" {
                functions.push(node);
            }
            pending.extend(named_children(node));
        }

        let function_name = format!("chain_{length}");
        let function = functions
            .iter()
            .copied()
            .find(|function| {
                function
                    .child_by_field_name("name")
                    .and_then(|name| rust_source.node_text(name))
                    == Some(function_name.as_str())
            })
            .expect("generated chain function exists");
        let mut pending = vec![function];
        let mut outer_call = None;
        while let Some(node) = pending.pop() {
            if node.kind() == "call_expression"
                && outer_call.is_none_or(|current: Node<'_>| {
                    node.end_byte() - node.start_byte() > current.end_byte() - current.start_byte()
                })
            {
                outer_call = Some(node);
            }
            pending.extend(named_children(node));
        }
        let call = outer_call.expect("generated chain has a call");
        let function = call.child_by_field_name("function").expect("call function");
        let receiver = function
            .child_by_field_name("value")
            .expect("modeled method has a receiver");
        let before = rust_source.expression_class_evaluations.get();
        let shapes_before = rust_source.modeled_call_shape_evaluations.get();
        let operation_limit = length * 8;
        rust_source
            .expression_class_evaluation_limit
            .set(Some(before + operation_limit));
        rust_source
            .modeled_call_shape_evaluation_limit
            .set(Some(shapes_before + operation_limit));
        let started = Instant::now();
        let owner = proof.receiver_owner(&rust_source, receiver);
        let elapsed = started.elapsed();
        let evaluations = rust_source.expression_class_evaluations.get() - before;
        let shape_evaluations = rust_source.modeled_call_shape_evaluations.get() - shapes_before;
        eprintln!(
            "chain_length={length} elapsed={elapsed:?} expression_class_evaluations={evaluations} modeled_call_shape_evaluations={shape_evaluations}"
        );
        assert_eq!(owner, None);
        assert!(
            evaluations <= operation_limit,
            "chain of {length} modeled calls evaluated {evaluations} uncached expressions"
        );
        assert!(
            shape_evaluations <= operation_limit,
            "chain of {length} modeled calls evaluated {shape_evaluations} uncached call shapes"
        );
    }

    #[test]
    fn imported_external_constructor_proves_grouped_cookie_pack_owner() {
        let source = "use cookie::{Cookie, CookieBuilder};\n\nfn run() {\n    Cookie::build((\"session\", \"value\"));\n    CookieBuilder::new((\"session\", \"value\"));\n}\n";
        let fixture = AnalyzerFixture::new_for_language(Language::Rust, &[("lib.rs", source)]);
        let pack: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../../semantic-packs/rust-codeql-parity/bifrost.rust-cookie.json"
        ))
        .expect("cookie model parses");
        activate_model_pack(&fixture, pack, "bifrost.rust-cookie", "cookie");
        let analyzer = fixture.analyzer.analyzer();
        let file = ProjectFile::new(fixture.project_root(), "lib.rs");
        let identities = ["build(", "new("]
            .into_iter()
            .map(|needle| {
                let start = source.find(needle).expect("fixture contains constructor");
                let rust_source = RustTypeProof::new(analyzer)
                    .expect("Rust type proof")
                    .source(&file)
                    .expect("prepared Rust source");
                let site = ResolvedReferenceSite {
                    path: needle[..needle.len() - 1].to_owned(),
                    text: needle[..needle.len() - 1].to_owned(),
                    range: Range {
                        start_byte: start,
                        end_byte: start + needle.len() - 1,
                        start_line: 0,
                        end_line: 0,
                    },
                    focus_start_byte: start,
                    focus_end_byte: start + needle.len() - 1,
                };
                let scope = AnalyzerQueryScope::new(analyzer);
                crate::analyzer::rust::external_calls::resolve_exact_rust_external_call_with_operation(
                    analyzer,
                    scope.token(),
                    &file,
                    rust_source.text(),
                    rust_source.tree(),
                    &site,
                    || None,
                    None,
                    None,
                    None,
                )
                .map(|(_, identity)| {
                    (
                        identity.owner_fqn().to_owned(),
                        identity.member().to_owned(),
                    )
                })
            })
            .collect::<Vec<_>>();
        assert_eq!(
            identities,
            vec![
                Some(("cookie.Cookie".to_owned(), "build".to_owned())),
                Some(("cookie.CookieBuilder".to_owned(), "new".to_owned())),
            ]
        );
    }

    fn activate_imported_constructor_model(fixture: &AnalyzerFixture) {
        let source = serde_json::json!({
            "schema_version": 2,
            "pack_id": "fixture.rust-imported-constructor",
            "version": "1.0.0",
            "producer": { "name": "rust-type-proof-test", "version": "1.0.0" },
            "language": "rust",
            "ecosystem": "cargo",
            "compatibility": { "bifrost": "*", "toolchains": [] },
            "provenance": { "source": "unit test" },
            "license": "NOASSERTION",
            "completeness": "complete",
            "safety": { "generated_code_only": false, "review_required": false },
            "shards": [{
                "id": "declarations.rust-imported-constructor",
                "activation": [{ "targets": [], "configurations": [] }],
                "payload": {
                    "kind": "declaration_facts",
                    "types": [
                        rust_type("std", "module"),
                        rust_type("std.process", "module"),
                        rust_type("std.process.Command", "struct"),
                        rust_type("std.vec", "module"),
                        rust_type("std.vec.Vec", "struct")
                    ],
                    "members": [rust_constructor(), rust_vec_constructor(), rust_method()],
                    "relations": []
                }
            }]
        });
        activate_model_pack(fixture, source, "fixture.rust-imported-constructor", "std");
    }

    fn activate_model_pack(
        fixture: &AnalyzerFixture,
        source: serde_json::Value,
        pack_id: &str,
        package: &str,
    ) {
        let pack = compile_source(
            SourceFormat::Json,
            &serde_json::to_vec(&source).expect("serialize Rust model fixture"),
            &CompilerOptions::default(),
        )
        .unwrap_or_else(|diagnostics| panic!("Rust model fixture must compile: {diagnostics:#?}"));
        let catalog = SemanticPackCatalog::open_ephemeral(Default::default())
            .expect("open semantic-pack catalog");
        catalog
            .register_session_pack(
                &pack,
                &SessionPackSource {
                    kind: SessionPackSourceKind::Embedded,
                    source_id: pack_id.to_owned(),
                },
            )
            .expect("register Rust model fixture");
        let request = SemanticModelActivationRequest {
            bifrost_version: semver::Version::parse(env!("CARGO_PKG_VERSION"))
                .expect("crate version parses"),
            evidence: vec![SemanticModelActivationEvidence {
                language: "rust".to_owned(),
                ecosystem: "cargo".to_owned(),
                package: Some(CatalogCoordinate {
                    name: package.to_owned(),
                    version: None,
                }),
                module: None,
                toolchain: None,
                target: None,
                configuration: None,
                artifact_sha256: None,
            }],
            controls: vec![SemanticModelActivationControl {
                scope: SemanticModelControlScope::Workspace,
                action: SemanticModelControlAction::Enable,
                selector: SemanticModelPackSelector {
                    pack_id: pack_id.to_owned(),
                    version: None,
                    manifest_digest: None,
                },
            }],
            limits: SemanticModelRuntimeLimits::default(),
        };
        assert!(matches!(
            acquire_active_semantic_models(
                fixture.analyzer.analyzer(),
                &catalog,
                None,
                &request,
                &crate::CancellationToken::new(),
            ),
            SemanticModelRuntimeOutcome::Ready { .. }
        ));
    }

    fn rust_type(name: &str, type_kind: &str) -> serde_json::Value {
        serde_json::json!({
            "id": format!(
                "type.fixture.{}",
                name.replace('.', "-").to_ascii_lowercase()
            ),
            "name": name,
            "type_kind": type_kind,
            "visibility": "public",
            "locator": {
                "kind": "artifact",
                "path": "library/std/src/lib.rs",
                "symbol": name
            }
        })
    }

    fn rust_constructor() -> serde_json::Value {
        serde_json::json!({
            "id": "member.fixture.std-process-command-new",
            "owner": "type.fixture.std-process-command",
            "name": "new",
            "member_kind": "method",
            "visibility": "public",
            "is_static": true,
            "callable_family_complete": true,
            "signature": {
                "parameters": [{
                    "name": "program",
                    "type": { "kind": "named", "name": "untyped" }
                }],
                "returns": { "kind": "named", "name": "std.process.Command" }
            },
            "locator": {
                "kind": "artifact",
                "path": "library/std/src/lib.rs",
                "symbol": "std.process.Command.new"
            }
        })
    }

    fn rust_path_constructor() -> serde_json::Value {
        serde_json::json!({
            "id": "member.fixture.std-path-path-new",
            "owner": "type.fixture.std-path-path",
            "name": "new",
            "member_kind": "method",
            "visibility": "public",
            "is_static": true,
            "callable_family_complete": true,
            "signature": {
                "parameters": [{
                    "name": "path",
                    "type": { "kind": "named", "name": "untyped" }
                }],
                "returns": { "kind": "named", "name": "std.path.Path" }
            },
            "locator": {
                "kind": "artifact",
                "path": "library/std/src/path.rs",
                "symbol": "std.path.Path.new"
            }
        })
    }

    fn rust_path_method() -> serde_json::Value {
        serde_json::json!({
            "id": "member.fixture.std-path-path-join",
            "owner": "type.fixture.std-path-path",
            "name": "join",
            "member_kind": "method",
            "visibility": "public",
            "is_static": false,
            "callable_family_complete": true,
            "signature": {
                "parameters": [{
                    "name": "path",
                    "type": { "kind": "named", "name": "untyped" }
                }],
                "returns": { "kind": "named", "name": "std.path.PathBuf" }
            },
            "locator": {
                "kind": "artifact",
                "path": "library/std/src/path.rs",
                "symbol": "std.path.Path.join"
            }
        })
    }

    fn rust_pathbuf_method() -> serde_json::Value {
        serde_json::json!({
            "id": "member.fixture.std-path-pathbuf-join",
            "owner": "type.fixture.std-path-pathbuf",
            "name": "join",
            "member_kind": "method",
            "visibility": "public",
            "is_static": false,
            "callable_family_complete": true,
            "signature": {
                "parameters": [{
                    "name": "path",
                    "type": { "kind": "named", "name": "untyped" }
                }],
                "returns": { "kind": "named", "name": "std.path.PathBuf" }
            },
            "locator": {
                "kind": "artifact",
                "path": "library/std/src/path.rs",
                "symbol": "std.path.PathBuf.join"
            }
        })
    }

    fn activate_path_chain_model(fixture: &AnalyzerFixture) {
        let pack = serde_json::json!({
            "schema_version": 2,
            "pack_id": "fixture.rust-path-chain",
            "version": "1.0.0",
            "producer": { "name": "rust-type-proof-test", "version": "1.0.0" },
            "language": "rust",
            "ecosystem": "cargo",
            "compatibility": { "bifrost": "*", "toolchains": [] },
            "provenance": { "source": "unit test" },
            "license": "NOASSERTION",
            "completeness": "complete",
            "safety": { "generated_code_only": false, "review_required": false },
            "shards": [{
                "id": "declarations.rust-path-chain",
                "activation": [{ "targets": [], "configurations": [] }],
                "payload": {
                    "kind": "declaration_facts",
                    "types": [
                        rust_type("std", "module"),
                        rust_type("std.path", "module"),
                        rust_type("std.path.Path", "struct"),
                        rust_type("std.path.PathBuf", "struct")
                    ],
                    "members": [
                        rust_path_constructor(),
                        rust_path_method(),
                        rust_pathbuf_method()
                    ],
                    "relations": []
                }
            }]
        });
        activate_model_pack(fixture, pack, "fixture.rust-path-chain", "std");
    }

    fn rust_vec_constructor() -> serde_json::Value {
        serde_json::json!({
            "id": "member.fixture.std-vec-vec-with-capacity",
            "owner": "type.fixture.std-vec-vec",
            "name": "with_capacity",
            "member_kind": "method",
            "visibility": "public",
            "is_static": true,
            "callable_family_complete": true,
            "signature": {
                "parameters": [{
                    "name": "capacity",
                    "type": { "kind": "named", "name": "untyped" }
                }],
                "returns": { "kind": "named", "name": "std.vec.Vec" }
            },
            "locator": {
                "kind": "artifact",
                "path": "library/alloc/src/vec/mod.rs",
                "symbol": "std.vec.Vec.with_capacity"
            }
        })
    }

    fn rust_method() -> serde_json::Value {
        serde_json::json!({
            "id": "member.fixture.std-process-command-arg",
            "owner": "type.fixture.std-process-command",
            "name": "arg",
            "member_kind": "method",
            "visibility": "public",
            "is_static": false,
            "callable_family_complete": true,
            "signature": {
                "parameters": [{
                    "name": "arg",
                    "type": { "kind": "named", "name": "untyped" }
                }],
                "returns": { "kind": "named", "name": "std.process.Command" }
            },
            "locator": {
                "kind": "artifact",
                "path": "library/std/src/process.rs",
                "symbol": "std.process.Command.arg"
            }
        })
    }
}
