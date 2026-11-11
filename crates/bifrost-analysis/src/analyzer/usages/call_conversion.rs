//! Resolver-proven per-actual applicability facts (#2724).
//!
//! Binding and conversion completeness are separate: matching a formal slot
//! does not establish its type. This query-local relation consumes the selected
//! declaration and the shared formal layout. Model overload selection also
//! requires competing signatures to be proven inapplicable.

use std::sync::Arc;

use crate::analyzer::common::language_for_file;
use crate::analyzer::languages::{LanguageSupport, language_support_for_hook};
use crate::analyzer::lexical_definitions::{
    formal_parameter_slots_for_owner_with_nodes, parameter_owner_for_range,
};
use crate::analyzer::semantic::{
    LengthDelimitedDigest, StableDigest, TransferKind, TransferOperation, ValuePreservation,
    ValueTransfer,
};
use crate::analyzer::semantic_model::{
    SemanticModelArgumentBinding, SemanticModelCallApplication, Signature, TypeRef,
    bind_semantic_model_arguments,
};
use crate::analyzer::usages::call_binding::{
    CallBindingKind, CallBindingMapping, CallBindingReport, CallBindingRow,
};
use crate::analyzer::usages::call_shape::CallShapeReport;
use crate::analyzer::usages::get_definition::parse_tree_for_language;
use crate::analyzer::{CodeUnit, IAnalyzer, Language, ProjectFile};
use crate::hash::HashMap;

/// Identity of an external declaration or a scope-proven static type.
///
/// This stores resolver evidence only. The language-specific producer owns
/// construction and interpretation (for example, Java decides which fully-qualified
/// names are primitive wrappers); the shared relation never infers meaning from a name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalConversionIdentity {
    fqn: String,
    provenance: ExternalConversionProvenance,
    /// Resolver-proven declaration kind retained as generic evidence. Java's
    /// producer uses this to distinguish a class wrapper from another type.
    declaration_is_class: bool,
    /// Identity of the effective external declaration surface. This is
    /// content scoped; the artifact path in `provenance` remains useful for
    /// diagnostics but is not the content proof by itself.
    external_surface_identity: StableDigest,
    /// Identity of the active semantic-model set, when one participated in
    /// resolving this declaration. A changed pack set must not reuse an old
    /// conversion proof.
    active_model_set_identity: Option<StableDigest>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub enum ExternalConversionProvenance {
    /// A complete native scope result or selected declaration supplies a static
    /// type term without claiming that an external class has been indexed.
    #[cfg(any(test, feature = "test-support"))]
    NativeStaticType {
        term: TypeRef,
        scope_identity: StableDigest,
    },
    SourceJar {
        artifact_path: std::path::PathBuf,
        source_path: String,
    },
    ClassFile {
        artifact_path: std::path::PathBuf,
        class_entry: String,
    },
    SemanticPack {
        pack_id: String,
        declaration_id: String,
    },
}

impl ExternalConversionIdentity {
    #[doc(hidden)]
    /// Construct an identity from resolver-owned artifact/model evidence.
    ///
    /// A semantic-pack declaration is not an exact identity without the active model-set
    /// digest, so construction refuses to produce one in that case.
    pub fn from_provenance(
        fqn: impl Into<String>,
        provenance: ExternalConversionProvenance,
        declaration_is_class: bool,
        external_surface_identity: StableDigest,
        active_model_set_identity: Option<StableDigest>,
    ) -> Option<Self> {
        if matches!(
            &provenance,
            ExternalConversionProvenance::SemanticPack { .. }
        ) && active_model_set_identity.is_none()
        {
            return None;
        }
        Some(Self {
            fqn: fqn.into(),
            provenance,
            declaration_is_class,
            external_surface_identity,
            active_model_set_identity,
        })
    }

    #[doc(hidden)]
    pub fn model_declaration(
        &self,
        overlay: &crate::analyzer::semantic_model::SemanticModelOverlay,
    ) -> Option<Arc<crate::analyzer::semantic_model::SemanticModelSymbol>> {
        let ExternalConversionProvenance::SemanticPack {
            pack_id,
            declaration_id,
        } = &self.provenance
        else {
            return None;
        };
        if self.active_model_set_identity
            != Some(StableDigest::sha256(
                overlay.active_model_set_hash().as_bytes(),
            ))
        {
            return None;
        }
        let matches = overlay.symbols_with_id(declaration_id);
        if matches!(
            matches.disposition,
            crate::analyzer::semantic_model::SemanticModelOverlayDisposition::Open(_)
        ) {
            return None;
        }
        let [symbol] = matches.records.as_slice() else {
            return None;
        };
        (symbol.provenance.pack_id == *pack_id
            && symbol.qualified_name == self.fqn
            && !symbol.provenance.ambiguous)
            .then(|| Arc::clone(symbol))
    }

    pub fn fqn(&self) -> &str {
        &self.fqn
    }

    #[doc(hidden)]
    pub fn digest(&self) -> StableDigest {
        let mut digest = LengthDelimitedDigest::new(b"bifrost.java.external-conversion.v1");
        digest.push(self.fqn.as_bytes());
        digest.push(if self.declaration_is_class {
            b"class".as_slice()
        } else {
            b"non-class".as_slice()
        });
        digest.push(self.external_surface_identity.as_bytes());
        match self.active_model_set_identity {
            Some(identity) => {
                digest.push(b"active-model-set");
                digest.push(identity.as_bytes());
            }
            None => digest.push(b"no-active-model-set"),
        }
        match &self.provenance {
            #[cfg(any(test, feature = "test-support"))]
            ExternalConversionProvenance::NativeStaticType {
                term,
                scope_identity,
            } => {
                digest.push(b"native-static-type");
                digest.push(scope_identity.as_bytes());
                digest.push(&serde_json::to_vec(term).expect("structured static type serializes"));
            }
            ExternalConversionProvenance::SourceJar {
                artifact_path,
                source_path,
            } => {
                digest.push(b"source-jar");
                digest.push(artifact_path.to_string_lossy().as_bytes());
                digest.push(source_path.as_bytes());
            }
            ExternalConversionProvenance::ClassFile {
                artifact_path,
                class_entry,
            } => {
                digest.push(b"class-file");
                digest.push(artifact_path.to_string_lossy().as_bytes());
                digest.push(class_entry.as_bytes());
            }
            ExternalConversionProvenance::SemanticPack {
                pack_id,
                declaration_id,
            } => {
                digest.push(b"semantic-pack");
                digest.push(pack_id.as_bytes());
                digest.push(declaration_id.as_bytes());
            }
        }
        digest.finish()
    }

    #[doc(hidden)]
    pub fn declaration_is_class(&self) -> bool {
        self.declaration_is_class
    }
}

/// Complete conversion evidence, a proven rejection, or unresolved applicability.
#[doc(hidden)]
pub enum ModelArgumentApplicability {
    Applicable(Box<ArgumentTypeConversion>),
    Inapplicable,
    Unknown(ConversionUnknown),
}

/// One actual or formal node with the file and source it was parsed from.
#[doc(hidden)]
#[derive(Clone, Copy)]
pub struct ConversionSyntax<'a> {
    pub file: &'a ProjectFile,
    pub node: tree_sitter::Node<'a>,
    pub source: &'a str,
}

/// Whether an unknown conversion may run user code when neither the actual
/// nor the formal could be read, as `language`'s prover answers it.
#[doc(hidden)]
pub fn unread_conversion_may_run_user_code(analyzer: &dyn IAnalyzer, language: Language) -> bool {
    language_support_for_hook(language, "call_argument_conversion_prover")
        .and_then(LanguageSupport::call_argument_conversion_prover)
        .is_some_and(|prover| {
            prover.unknown_conversion_may_run_user_code(
                analyzer,
                &CallConversionCache::default(),
                None,
                None,
            )
        })
}

/// Optional access to the provider's retention-budgeted lexical index cache.
/// Entries are content-keyed and evictable. Reference contexts use the supplied
/// tree without loading source; build work alone is charged to the request.
#[doc(hidden)]
pub struct CallConversionContext<'a> {
    cache: &'a CallConversionCache,
    indexes: Option<crate::analyzer::lexical_definitions::LexicalIndexCache>,
}

impl<'a> CallConversionContext<'a> {
    pub fn reference(cache: &'a CallConversionCache) -> Self {
        Self {
            cache,
            indexes: None,
        }
    }

    pub fn lexical_binding(
        &self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        focus: tree_sitter::Node<'_>,
        source: &str,
        identifier: &str,
    ) -> Option<crate::analyzer::lexical_definitions::LexicalBindingResolution> {
        // The root-based reference entry refused an empty identifier, and an
        // empty name must not match a grammar recovery node's empty text.
        if identifier.is_empty() {
            return None;
        }
        if self.indexes.is_none() {
            return crate::analyzer::lexical_definitions::resolve_lexical_binding_with_candidate_index(
                language_for_file(file), focus, source, focus.start_byte(), identifier, None,
            ).ok().flatten();
        }
        let parsed = self.cache.source(analyzer, file)?;
        let mut root = focus;
        while let Some(parent) = root.parent() {
            root = parent;
        }
        if root.id() == parsed.tree.root_node().id() {
            let mut index =
                crate::analyzer::lexical_definitions::LexicalScopeCandidateIndex::shared(
                    self.indexes.as_ref().unwrap().clone(),
                    parsed.parse_census,
                );
            #[cfg(any(test, feature = "test-support"))]
            let before = index.work();
            let result =
                crate::analyzer::lexical_definitions::resolve_lexical_binding_with_candidate_index(
                    language_for_file(file),
                    focus,
                    &parsed.source,
                    focus.start_byte(),
                    identifier,
                    Some(&mut index),
                )
                .ok()
                .flatten();
            // A derived index of an immutable tree is not charged to the
            // request: the build lands on whichever request first fills a
            // scope, so charging it would make work counters depend on cache
            // history (#11053). The test counters below observe it instead.
            #[cfg(any(test, feature = "test-support"))]
            let after = index.work();
            #[cfg(any(test, feature = "test-support"))]
            {
                let mut total = self.cache.lexical_work.lock().unwrap();
                total.scope_builds += after.scope_builds - before.scope_builds;
                total.build_visits += after.build_visits - before.build_visits;
                total.candidate_examinations +=
                    after.candidate_examinations - before.candidate_examinations;
            }
            result
        } else {
            crate::analyzer::lexical_definitions::resolve_lexical_binding_with_candidate_index(
                language_for_file(file),
                focus,
                source,
                focus.start_byte(),
                identifier,
                None,
            )
            .ok()
            .flatten()
        }
    }
}

impl std::ops::Deref for CallConversionContext<'_> {
    type Target = CallConversionCache;
    fn deref(&self) -> &Self::Target {
        self.cache
    }
}

/// Language-owned call-argument conversion producer.
///
/// The shared relation owns exact call/signature/actual/formal joins and delegates only
/// owner applicability and one AST-backed actual/formal proof to the selected language.
#[doc(hidden)]
pub trait CallArgumentConversionProver: Send + Sync {
    /// Whether one argument proof requires applicability at every sibling.
    fn requires_complete_signature_for_argument_proofs(&self) -> bool {
        true
    }

    /// Validate applicability constraints owned by the formal language syntax.
    fn validate_owner(&self, _owner: tree_sitter::Node<'_>) -> Result<(), ConversionUnknown> {
        Ok(())
    }

    /// Prove one actual-to-formal pair from the language's resolver and AST evidence.
    #[allow(clippy::too_many_arguments)]
    fn prove_argument(
        &self,
        analyzer: &dyn IAnalyzer,
        sources: &CallConversionContext<'_>,
        file: &ProjectFile,
        actual: tree_sitter::Node<'_>,
        source: &str,
        formal_file: &ProjectFile,
        formal: tree_sitter::Node<'_>,
        formal_source: &str,
    ) -> Result<ArgumentTypeConversion, ConversionUnknown>;

    /// Whether a conversion this prover could not establish may run user
    /// code. This caller-side obligation is independent of binding lookup
    /// uncertainty. `None` marks unread actual or formal syntax. Languages whose argument
    /// conversions never run user code keep the default.
    fn unknown_conversion_may_run_user_code(
        &self,
        _analyzer: &dyn IAnalyzer,
        _sources: &CallConversionCache,
        _actual: Option<ConversionSyntax<'_>>,
        _formal: Option<ConversionSyntax<'_>>,
    ) -> bool {
        false
    }

    /// Prove one actual against a structured model signature formal. The
    /// language adapter owns interpretation of the model's `TypeRef`; the
    /// shared relation never compares rendered type spellings.
    #[allow(clippy::too_many_arguments)]
    fn prove_model_argument(
        &self,
        _analyzer: &dyn IAnalyzer,
        _file: &ProjectFile,
        _actual: tree_sitter::Node<'_>,
        _source: &str,
        _formal_type: &TypeRef,
    ) -> Result<ArgumentTypeConversion, ConversionUnknown> {
        Err(ConversionUnknown::UnsupportedConversion)
    }

    /// A language with phased invocation rules selects its overload and supplies
    /// the corresponding actual-to-formal type layout. The shared consumer
    /// retains AST extraction, binding joins and conversion fact publication.
    fn select_model_invocation(
        &self,
        _analyzer: &dyn IAnalyzer,
        _file: &ProjectFile,
        _actuals: &[tree_sitter::Node<'_>],
        _source: &str,
        _signatures: &[Signature],
    ) -> Option<Result<(usize, Vec<TypeRef>), ConversionUnknown>> {
        None
    }

    /// An unsupported conversion is not a proof that an overload is inapplicable.
    /// Languages may reject a candidate only from complete conversion rules and
    /// resolved type identities; the default preserves every failure as unknown.
    fn model_argument_applicability(
        &self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        actual: tree_sitter::Node<'_>,
        source: &str,
        formal_type: &TypeRef,
    ) -> ModelArgumentApplicability {
        match self.prove_model_argument(analyzer, file, actual, source, formal_type) {
            Ok(proof) => ModelArgumentApplicability::Applicable(Box::new(proof)),
            Err(reason) => ModelArgumentApplicability::Unknown(reason),
        }
    }

    /// Whether an applicable member whose every formal is identical to its
    /// actual's static type is better than every other member that can apply,
    /// whether or not the other member's applicability is decided. C# has
    /// this rule (an expression that exactly matches its parameter type is a
    /// better conversion than any that does not, ECMA-334 12.6.4.5), so a
    /// user-defined conversion the prover cannot see never displaces the
    /// exact match. The default proves nothing.
    fn exact_match_is_best_member(&self) -> bool {
        false
    }

    /// Whether `specific` is proven strictly more specific than `other` for a
    /// positional application of `arity` actuals, under the language's
    /// overload resolution rules. The caller has proven `specific` applicable
    /// by fixed-arity invocation; `other` is applicable or undecided. Only a
    /// proof counts: the default proves nothing, so overload selection stays
    /// ambiguous.
    fn model_signature_more_specific(
        &self,
        _analyzer: &dyn IAnalyzer,
        _file: &ProjectFile,
        _arity: u32,
        _specific: &Signature,
        _other: &Signature,
    ) -> bool {
        false
    }
}

pub use brokk_bifrost_jvm::java::primitives::JavaPrimitive;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CSharpPrimitive {
    Char,
    Int32,
    String,
}

/// A C# type identity that its spelling fixes without name lookup: a
/// predefined-type keyword or a fully qualified name, and single-dimensional
/// arrays of those. The three built-ins with conversion rules keep their
/// primitive identity; every other name is its CLR metadata name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CSharpConversionType {
    Primitive(CSharpPrimitive),
    Nominal(Box<str>),
    Array(Box<Self>),
}

impl CSharpConversionType {
    fn digest(&self) -> StableDigest {
        let mut digest = LengthDelimitedDigest::new(b"bifrost.csharp.conversion-type.v1");
        let mut pending = self;
        loop {
            match pending {
                Self::Primitive(primitive) => {
                    digest.push(b"primitive");
                    digest.push(&[*primitive as u8]);
                    break;
                }
                Self::Nominal(name) => {
                    digest.push(b"nominal");
                    digest.push(name.as_bytes());
                    break;
                }
                Self::Array(element) => {
                    digest.push(b"array");
                    pending = element;
                }
            }
        }
        digest.finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeScriptPrimitive {
    Boolean,
    Number,
    String,
    BigInt,
    Symbol,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RustPrimitive {
    Bool,
    Char,
    Str,
    U8,
    U16,
    U32,
    U64,
    U128,
    Usize,
    I8,
    I16,
    I32,
    I64,
    I128,
    Isize,
    F32,
    F64,
}

/// Structured Scala conversion types. Identities are resolver- or
/// declaration-backed; prelude names such as `Int` keep their structured
/// segment path rather than a displayed spelling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScalaConversionType {
    /// Nominal type path (`Int`, `scala.Predef.String`, `Wrapper`).
    Nominal(Box<[Box<str>]>),
    Declaration(CodeUnit),
}

impl ScalaConversionType {
    fn digest(&self) -> StableDigest {
        let mut digest = LengthDelimitedDigest::new(b"bifrost.scala.conversion-type.v1");
        match self {
            Self::Nominal(segments) => {
                digest.push(b"nominal");
                digest.push(&(segments.len() as u64).to_be_bytes());
                for segment in segments {
                    digest.push(segment.as_bytes());
                }
            }
            Self::Declaration(unit) => {
                digest.push(b"declaration");
                digest.push(unit.declaration_id().as_str().as_bytes());
            }
        }
        digest.finish()
    }
}

/// Structured Rust conversion types. The language producer bounds nesting
/// before construction; references describe conversion shape, not a proof of
/// borrow validity or region inference. Nominals retain resolved declarations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RustConversionType {
    Primitive(RustPrimitive),
    Declaration(CodeUnit),
    AppliedDeclaration {
        declaration: CodeUnit,
        arguments: Vec<Self>,
    },
    /// Exact nominal identity from one captured active model set.
    Model {
        model_set: String,
        symbol: String,
        arguments: Vec<Self>,
    },
    Reference {
        mutable: bool,
        referent: Box<Self>,
    },
    Array {
        element: Box<Self>,
        length: u64,
    },
    Slice {
        element: Box<Self>,
    },
    Tuple(Vec<Self>),
    Unit,
}

/// Partial selected-type proof used only by qualifying-type queries.
/// Complete conversion APIs and their digests cannot accept this carrier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RustProjectedType {
    Primitive(RustPrimitive),
    Declaration(CodeUnit),
    AppliedDeclaration {
        declaration: CodeUnit,
        arguments: Vec<Self>,
    },
    /// Exact nominal identity from one captured active model set.
    Model {
        model_set: String,
        symbol: String,
        arguments: Vec<Self>,
    },
    Reference {
        mutable: bool,
        referent: Box<Self>,
    },
    Array {
        element: Box<Self>,
        length: u64,
    },
    Slice {
        element: Box<Self>,
    },
    Tuple(Vec<Self>),
    Unit,
    /// A component whose canonical type has not been proved.
    Unknown(ConversionUnknown),
}

impl From<RustConversionType> for RustProjectedType {
    fn from(value: RustConversionType) -> Self {
        match value {
            RustConversionType::Primitive(value) => Self::Primitive(value),
            RustConversionType::Declaration(value) => Self::Declaration(value),
            RustConversionType::AppliedDeclaration {
                declaration,
                arguments,
            } => Self::AppliedDeclaration {
                declaration,
                arguments: arguments.into_iter().map(Self::from).collect(),
            },
            RustConversionType::Model {
                model_set,
                symbol,
                arguments,
            } => Self::Model {
                model_set,
                symbol,
                arguments: arguments.into_iter().map(Self::from).collect(),
            },
            RustConversionType::Reference { mutable, referent } => Self::Reference {
                mutable,
                referent: Box::new(Self::from(*referent)),
            },
            RustConversionType::Array { element, length } => Self::Array {
                element: Box::new(Self::from(*element)),
                length,
            },
            RustConversionType::Slice { element } => Self::Slice {
                element: Box::new(Self::from(*element)),
            },
            RustConversionType::Tuple(values) => {
                Self::Tuple(values.into_iter().map(Self::from).collect())
            }
            RustConversionType::Unit => Self::Unit,
        }
    }
}

impl RustProjectedType {
    /// Recover the original complete identity only when every component is proved.
    pub fn into_complete(self) -> Result<RustConversionType, ConversionUnknown> {
        Ok(match self {
            Self::Primitive(value) => RustConversionType::Primitive(value),
            Self::Declaration(value) => RustConversionType::Declaration(value),
            Self::AppliedDeclaration {
                declaration,
                arguments,
            } => RustConversionType::AppliedDeclaration {
                declaration,
                arguments: arguments
                    .into_iter()
                    .map(Self::into_complete)
                    .collect::<Result<_, _>>()?,
            },
            Self::Model {
                model_set,
                symbol,
                arguments,
            } => RustConversionType::Model {
                model_set,
                symbol,
                arguments: arguments
                    .into_iter()
                    .map(Self::into_complete)
                    .collect::<Result<_, _>>()?,
            },
            Self::Reference { mutable, referent } => RustConversionType::Reference {
                mutable,
                referent: Box::new(referent.into_complete()?),
            },
            Self::Array { element, length } => RustConversionType::Array {
                element: Box::new(element.into_complete()?),
                length,
            },
            Self::Slice { element } => RustConversionType::Slice {
                element: Box::new(element.into_complete()?),
            },
            Self::Tuple(values) => RustConversionType::Tuple(
                values
                    .into_iter()
                    .map(Self::into_complete)
                    .collect::<Result<_, _>>()?,
            ),
            Self::Unit => RustConversionType::Unit,
            Self::Unknown(reason) => return Err(reason),
        })
    }
}

/// Query-local qualifying-type evidence. Each path names one canonical type
/// component; this certificate has no complete-answer memo or digest API.
pub struct RustQualifyingTypeProof {
    pub ty: RustProjectedType,
    pub components: Vec<(
        Vec<usize>,
        Arc<crate::analyzer::i_analyzer::QueryReadReceipt>,
    )>,
}

impl RustQualifyingTypeProof {
    /// Replay only the components used to decide the constraint.
    pub fn replay(&self, analyzer: &dyn IAnalyzer, paths: &[Vec<usize>]) {
        for (path, receipt) in &self.components {
            if paths.contains(path) {
                receipt.replay(analyzer);
            }
        }
    }
}

impl RustConversionType {
    fn digest(&self) -> StableDigest {
        let mut digest = LengthDelimitedDigest::new(b"bifrost.rust.conversion-type.v1");
        let mut pending = vec![self];
        while let Some(ty) = pending.pop() {
            match ty {
                Self::Primitive(primitive) => {
                    digest.push(b"primitive");
                    digest.push(&[*primitive as u8]);
                }
                Self::Declaration(unit) => {
                    digest.push(b"declaration");
                    digest.push(unit.declaration_id().as_str().as_bytes());
                }
                Self::AppliedDeclaration {
                    declaration,
                    arguments,
                } => {
                    digest.push(b"applied_declaration");
                    digest.push(declaration.declaration_id().as_str().as_bytes());
                    digest.push(&(arguments.len() as u64).to_be_bytes());
                    pending.extend(arguments.iter().rev());
                }
                Self::Model {
                    model_set,
                    symbol,
                    arguments,
                } => {
                    digest.push(b"model");
                    digest.push(model_set.as_bytes());
                    digest.push(symbol.as_bytes());
                    digest.push(&(arguments.len() as u64).to_be_bytes());
                    pending.extend(arguments.iter().rev());
                }
                Self::Reference { mutable, referent } => {
                    digest.push(b"reference");
                    digest.push(&[u8::from(*mutable)]);
                    pending.push(referent);
                }
                Self::Array { element, length } => {
                    digest.push(b"array");
                    digest.push(&length.to_be_bytes());
                    pending.push(element);
                }
                Self::Slice { element } => {
                    digest.push(b"slice");
                    pending.push(element);
                }
                Self::Tuple(elements) => {
                    digest.push(b"tuple");
                    digest.push(&(elements.len() as u64).to_be_bytes());
                    pending.extend(elements.iter().rev());
                }
                Self::Unit => digest.push(b"unit"),
            }
        }
        digest.finish()
    }
}

/// Resolved identities, rather than parser-derived names or displayed types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedConversionType {
    JavaPrimitive(JavaPrimitive),
    CSharpPrimitive(CSharpPrimitive),
    /// A C# nominal or array identity; built-ins use `CSharpPrimitive`.
    CSharp(CSharpConversionType),
    TypeScriptPrimitive(TypeScriptPrimitive),
    Rust(RustConversionType),
    Scala(ScalaConversionType),
    Declaration(CodeUnit),
    /// Exact artifact/model declaration identity supplied by the resolver.
    External {
        identity: ExternalConversionIdentity,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConversionKind {
    JavaIdentity,
    JavaPrimitiveWidening,
    JavaReferenceWidening,
    JavaBoxing,
    JavaUnboxing,
    CSharpIdentity,
    CSharpImplicitNumeric,
    TypeScriptIdentity,
    TypeScriptStructuralAssignability,
    RustIdentity,
    RustDeref,
    RustUnsizing,
    RustReborrow,
    ScalaIdentity,
    ScalaImplicitConversion,
    ScalaValueClassBoxing,
    ScalaValueClassUnboxing,
    ScalaOpaqueAdaptation,
}

impl ConversionKind {
    pub const LABELS: &'static [&'static str] = &[
        "java_identity",
        "java_primitive_widening",
        "java_reference_widening",
        "java_boxing",
        "java_unboxing",
        "csharp_identity",
        "csharp_implicit_numeric",
        "typescript_identity",
        "typescript_structural_assignability",
        "rust_identity",
        "rust_deref",
        "rust_unsizing",
        "rust_reborrow",
        "scala_identity",
        "scala_implicit_conversion",
        "scala_value_class_boxing",
        "scala_value_class_unboxing",
        "scala_opaque_adaptation",
    ];

    /// Whether the actual's type is the formal's type.
    pub const fn is_identity(self) -> bool {
        matches!(
            self,
            Self::JavaIdentity
                | Self::CSharpIdentity
                | Self::TypeScriptIdentity
                | Self::RustIdentity
                | Self::ScalaIdentity
        )
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::JavaIdentity => "java_identity",
            Self::JavaPrimitiveWidening => "java_primitive_widening",
            Self::JavaReferenceWidening => "java_reference_widening",
            Self::JavaBoxing => "java_boxing",
            Self::JavaUnboxing => "java_unboxing",
            Self::CSharpIdentity => "csharp_identity",
            Self::CSharpImplicitNumeric => "csharp_implicit_numeric",
            Self::TypeScriptIdentity => "typescript_identity",
            Self::TypeScriptStructuralAssignability => "typescript_structural_assignability",
            Self::RustIdentity => "rust_identity",
            Self::RustDeref => "rust_deref",
            Self::RustUnsizing => "rust_unsizing",
            Self::RustReborrow => "rust_reborrow",
            Self::ScalaIdentity => "scala_identity",
            Self::ScalaImplicitConversion => "scala_implicit_conversion",
            Self::ScalaValueClassBoxing => "scala_value_class_boxing",
            Self::ScalaValueClassUnboxing => "scala_value_class_unboxing",
            Self::ScalaOpaqueAdaptation => "scala_opaque_adaptation",
        }
    }
}

pub use crate::analyzer::semantic::call_conversion::ConversionUnknown;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArgumentTypeConversion {
    pub source: ResolvedConversionType,
    pub target: ResolvedConversionType,
    pub kind: ConversionKind,
    pub hierarchy: Option<crate::analyzer::semantic_model::JavaHierarchyAnswer>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConversionProof {
    ResolverProven,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConversionCompleteness {
    /// Exhaustive for this actual/formal typing relation, not runtime behavior.
    CompleteForPair,
    Unknown(ConversionUnknown),
}

/// The result is complete only for conversion typing of this actual/formal
/// pair. It does not close dispatch, exceptions (including null unboxing),
/// wrapper allocation/cache identity, or the enclosing procedure's behavior.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallArgumentConversion {
    pub site_id: String,
    pub selected_signature: Option<String>,
    pub target: Option<CodeUnit>,
    /// The exact unmaterialized model target selected by dispatch. This is
    /// disjoint from `target`: a model fact can never join to a source
    /// declaration merely because the source has no range identity.
    pub model_target_id: Option<String>,
    pub argument_id: Option<String>,
    pub formal_index: Option<usize>,
    pub result: Result<ArgumentTypeConversion, ConversionUnknown>,
    pub proof: ConversionProof,
    pub completeness: ConversionCompleteness,
    operation_id: Option<StableDigest>,
}

impl CallArgumentConversion {
    pub(crate) fn unknown(
        row: &CallBindingRow,
        target: Option<&CodeUnit>,
        signature: Option<&str>,
        reason: ConversionUnknown,
    ) -> Self {
        Self {
            site_id: row.site_id.clone(),
            selected_signature: signature.map(str::to_owned),
            target: target.cloned(),
            model_target_id: None,
            argument_id: row.argument_id.clone(),
            formal_index: row.formal_index,
            result: Err(reason),
            proof: ConversionProof::Unknown,
            completeness: ConversionCompleteness::Unknown(reason),
            operation_id: None,
        }
    }

    pub(crate) fn unknown_model(
        row: &CallBindingRow,
        model_target_id: &str,
        signature: Option<&str>,
        reason: ConversionUnknown,
    ) -> Self {
        let mut fact = Self::unknown(row, None, signature, reason);
        fact.model_target_id = Some(model_target_id.to_owned());
        fact
    }

    /// A proven result has exhaustive typing evidence for this pair; unknown
    /// results retain the typed prerequisite that was missing.
    pub fn is_proven(&self) -> bool {
        self.result.is_ok()
    }

    pub fn operation(&self) -> Option<TransferOperation> {
        self.operation_id
            .map(TransferOperation::CallArgumentConversion)
    }

    /// Consumer seam for value-flow lowering. Identity and structural reference
    /// adjustments preserve aliasing and therefore emit no identity barrier.
    /// The caller must separately retain exceptional and allocation uncertainty.
    pub fn transfer(&self) -> Option<ValueTransfer> {
        let conversion = self.result.as_ref().ok()?;
        let kind = match conversion.kind {
            ConversionKind::JavaBoxing | ConversionKind::ScalaValueClassBoxing => {
                TransferKind::Boxing
            }
            ConversionKind::JavaUnboxing | ConversionKind::ScalaValueClassUnboxing => {
                TransferKind::Unboxing
            }
            ConversionKind::JavaPrimitiveWidening => {
                use JavaPrimitive::{Double, Float, Int, Long};
                let changing = matches!(
                    (&conversion.source, &conversion.target),
                    (
                        ResolvedConversionType::JavaPrimitive(Int | Long),
                        ResolvedConversionType::JavaPrimitive(Float)
                    ) | (
                        ResolvedConversionType::JavaPrimitive(Long),
                        ResolvedConversionType::JavaPrimitive(Double)
                    )
                );
                TransferKind::Conversion {
                    preservation: if changing {
                        ValuePreservation::Changing
                    } else {
                        ValuePreservation::Preserving
                    },
                }
            }
            ConversionKind::CSharpImplicitNumeric => TransferKind::Conversion {
                preservation: ValuePreservation::Preserving,
            },
            ConversionKind::ScalaImplicitConversion => TransferKind::Conversion {
                preservation: ValuePreservation::Changing,
            },
            ConversionKind::ScalaOpaqueAdaptation => TransferKind::Conversion {
                preservation: ValuePreservation::Preserving,
            },
            ConversionKind::JavaIdentity
            | ConversionKind::JavaReferenceWidening
            | ConversionKind::CSharpIdentity
            | ConversionKind::TypeScriptIdentity
            | ConversionKind::TypeScriptStructuralAssignability
            | ConversionKind::RustIdentity
            | ConversionKind::RustDeref
            | ConversionKind::RustUnsizing
            | ConversionKind::RustReborrow
            | ConversionKind::ScalaIdentity => return None,
        };
        Some(ValueTransfer {
            kind,
            operation: self
                .operation()
                .expect("proven conversions own an operation"),
        })
    }

    fn establish(&mut self, conversion: ArgumentTypeConversion) {
        let mut digest = LengthDelimitedDigest::new(b"bifrost.call_argument_conversion.v1");
        digest.push(self.site_id.as_bytes());
        digest.push(
            self.selected_signature
                .as_ref()
                .expect("selected signature")
                .as_bytes(),
        );
        let target_id = self
            .target
            .as_ref()
            .map(|target| target.declaration_id().to_owned());
        digest.push(match (&target_id, &self.model_target_id) {
            (Some(target_id), None) => target_id.as_str().as_bytes(),
            (None, Some(model_target_id)) => model_target_id.as_bytes(),
            _ => unreachable!("a conversion fact joins exactly one target kind"),
        });
        digest.push(self.argument_id.as_ref().expect("source actual").as_bytes());
        digest.push(&(self.formal_index.expect("bound formal") as u64).to_be_bytes());
        for identity in [&conversion.source, &conversion.target] {
            match identity {
                ResolvedConversionType::JavaPrimitive(primitive) => {
                    digest.push(b"java_primitive");
                    digest.push(&[*primitive as u8]);
                }
                ResolvedConversionType::CSharpPrimitive(primitive) => {
                    digest.push(b"csharp_primitive");
                    digest.push(&[*primitive as u8]);
                }
                ResolvedConversionType::CSharp(identity) => {
                    digest.push(b"csharp");
                    digest.push(identity.digest().as_bytes());
                }
                ResolvedConversionType::TypeScriptPrimitive(primitive) => {
                    digest.push(b"typescript_primitive");
                    digest.push(&[*primitive as u8]);
                }
                ResolvedConversionType::Rust(identity) => {
                    digest.push(b"rust");
                    digest.push(identity.digest().as_bytes());
                }
                ResolvedConversionType::Scala(identity) => {
                    digest.push(b"scala");
                    digest.push(identity.digest().as_bytes());
                }
                ResolvedConversionType::Declaration(unit) => {
                    digest.push(b"declaration");
                    digest.push(unit.declaration_id().as_str().as_bytes());
                }
                ResolvedConversionType::External { identity } => {
                    digest.push(b"external");
                    digest.push(identity.digest().as_bytes());
                }
            }
        }
        digest.push(conversion.kind.label().as_bytes());
        self.operation_id = Some(digest.finish());
        self.result = Ok(conversion);
        self.proof = ConversionProof::ResolverProven;
        self.completeness = ConversionCompleteness::CompleteForPair;
    }
}

type IndexedConversionProof = (usize, Result<ArgumentTypeConversion, ConversionUnknown>);

pub struct ConversionSource {
    pub source: Arc<str>,
    pub tree: tree_sitter::Tree,
    pub(crate) preparation: super::get_definition::PreparedDefinitionSource,
    parse_census: StableDigest,
    pub(crate) shape_census: StableDigest,
}

impl ConversionSource {
    /// The census names the file as well as its content: each file holds its
    /// own source and tree, so files with identical bytes are charged once each.
    fn new(file: &ProjectFile, source: Arc<str>, tree: tree_sitter::Tree) -> Self {
        let content = StableDigest::sha256(source.as_bytes());
        let path = file.rel_path().to_string_lossy();
        let mut parse = LengthDelimitedDigest::new(b"bifrost.rust.conversion-parse-census.v2");
        parse.push(path.as_bytes());
        parse.push(content.as_bytes());
        let mut shape = LengthDelimitedDigest::new(b"bifrost.rust.conversion-shape-census.v2");
        shape.push(path.as_bytes());
        shape.push(content.as_bytes());
        let preparation =
            super::get_definition::PreparedDefinitionSource::new(Arc::clone(&source), tree.clone());
        Self {
            source,
            tree,
            preparation,
            parse_census: parse.finish(),
            shape_census: shape.finish(),
        }
    }

    pub(crate) fn charge_shape(
        &self,
        nodes: usize,
        budget: &mut crate::analyzer::semantic::SemanticBudget,
    ) -> Result<
        crate::analyzer::semantic::SemanticWork,
        crate::analyzer::semantic::SemanticBudgetExceeded,
    > {
        let full = crate::analyzer::semantic::SemanticWork {
            nested_entries: nodes,
            ..Default::default()
        };
        let work = if budget.has_charged_artifact(self.shape_census) {
            crate::analyzer::semantic::SemanticWork {
                nested_entries: 1,
                ..Default::default()
            }
        } else {
            full
        };
        budget.charge_complete_artifact_hit(self.shape_census, full)?;
        Ok(work)
    }

    pub(crate) fn charge_parse(
        &self,
        budget: &mut crate::analyzer::semantic::SemanticBudget,
    ) -> Result<
        crate::analyzer::semantic::SemanticWork,
        crate::analyzer::semantic::SemanticBudgetExceeded,
    > {
        let full = crate::analyzer::semantic::SemanticWork {
            source_bytes: self.source.len(),
            ..Default::default()
        };
        let work = if budget.has_charged_artifact(self.parse_census) {
            crate::analyzer::semantic::SemanticWork {
                nested_entries: 1,
                ..Default::default()
            }
        } else {
            full
        };
        budget.charge_complete_artifact_hit(self.parse_census, full)?;
        Ok(work)
    }
}

fn is_explicit_conversion_row(row: &CallBindingRow) -> bool {
    row.argument_id.is_some()
        && !matches!(
            row.binding_kind,
            Some(CallBindingKind::Receiver | CallBindingKind::Implicit)
        )
}

fn exact_positional_formal_index(row: &CallBindingRow) -> Result<usize, ConversionUnknown> {
    if row.mapping != CallBindingMapping::Exact
        || row.binding_kind != Some(CallBindingKind::Positional)
    {
        return Err(ConversionUnknown::AmbiguousBinding);
    }
    row.formal_index.ok_or(ConversionUnknown::AmbiguousBinding)
}

fn exact_argument_expression<'tree>(
    source: &'tree ConversionSource,
    row: &CallBindingRow,
) -> Result<tree_sitter::Node<'tree>, ConversionUnknown> {
    let actual = source
        .tree
        .root_node()
        .named_descendant_for_byte_range(row.range.start_byte, row.range.end_byte)
        .filter(|node| node.byte_range() == (row.range.start_byte..row.range.end_byte))
        .ok_or(ConversionUnknown::UnsupportedExpression)?;
    if actual.has_error() || actual.is_missing() {
        return Err(ConversionUnknown::UnsupportedExpression);
    }
    Ok(actual)
}

fn model_conversion_prover(
    file: &ProjectFile,
) -> Result<&'static dyn CallArgumentConversionProver, ConversionUnknown> {
    language_support_for_hook(language_for_file(file), "call_argument_conversion_prover")
        .and_then(LanguageSupport::call_argument_conversion_prover)
        .ok_or(ConversionUnknown::UnsupportedLanguage)
}

/// The written positional actuals of a model call, in source order.
fn written_model_actuals<'tree>(
    source: &'tree ConversionSource,
    shape: &CallShapeReport,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<tree_sitter::Node<'tree>>, ConversionUnknown> {
    let mut written = Vec::new();
    for argument in &shape.arguments {
        if is_cancelled() {
            return Err(ConversionUnknown::Cancelled);
        }
        if argument.spread || argument.name.is_some() {
            return Err(ConversionUnknown::AmbiguousBinding);
        }
        let actual = source
            .tree
            .root_node()
            .named_descendant_for_byte_range(argument.range.start_byte, argument.range.end_byte)
            .filter(|node| {
                node.byte_range() == (argument.range.start_byte..argument.range.end_byte)
            })
            .ok_or(ConversionUnknown::UnsupportedExpression)?;
        if actual.has_error() || actual.is_missing() {
            return Err(ConversionUnknown::UnsupportedExpression);
        }
        written.push(actual);
    }
    Ok(written)
}

enum ModelCandidateApplicability {
    /// Every actual converts; `exact` when every conversion is an identity.
    Applicable {
        exact: bool,
    },
    /// Some actual provably does not convert to its formal.
    Rejected,
    /// The written application does not fit the member's formal layout.
    LayoutMismatch,
    Unknown(Vec<ConversionUnknown>),
}

/// Applicability of one model member to the written positional actuals. The
/// error channel carries only cancellation and budget exhaustion.
fn model_candidate_applicability(
    prover: &dyn CallArgumentConversionProver,
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    written: &[tree_sitter::Node<'_>],
    signature: &Signature,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<ModelCandidateApplicability, ConversionUnknown> {
    if is_cancelled() {
        return Err(ConversionUnknown::Cancelled);
    }
    let application = SemanticModelCallApplication::positional(
        u32::try_from(written.len()).expect("written call arity must fit u32"),
    );
    let parameter_ordinals = match bind_semantic_model_arguments(signature, &application) {
        SemanticModelArgumentBinding::Exact { parameter_ordinals } => parameter_ordinals,
        SemanticModelArgumentBinding::Mismatch => {
            return Ok(ModelCandidateApplicability::LayoutMismatch);
        }
        SemanticModelArgumentBinding::PossibleSpread => {
            return Ok(ModelCandidateApplicability::Unknown(vec![
                ConversionUnknown::AmbiguousBinding,
            ]));
        }
    };
    let mut rejected = false;
    let mut exact = true;
    let mut unknown = Vec::new();
    for (actual, formal_index) in written.iter().zip(parameter_ordinals) {
        if is_cancelled() {
            return Err(ConversionUnknown::Cancelled);
        }
        let formal = &signature.parameters[formal_index];
        // Variadic conversion requires language-owned expansion semantics.
        if formal.variadic {
            unknown.push(ConversionUnknown::UnsupportedConversion);
            continue;
        }
        match prover.model_argument_applicability(analyzer, file, *actual, source, &formal.r#type) {
            ModelArgumentApplicability::Applicable(proof) => exact &= proof.kind.is_identity(),
            ModelArgumentApplicability::Inapplicable => rejected = true,
            ModelArgumentApplicability::Unknown(
                reason @ (ConversionUnknown::Cancelled | ConversionUnknown::BudgetExhausted),
            ) => return Err(reason),
            ModelArgumentApplicability::Unknown(reason) => unknown.push(reason),
        }
    }
    Ok(if rejected {
        ModelCandidateApplicability::Rejected
    } else if unknown.is_empty() {
        ModelCandidateApplicability::Applicable { exact }
    } else {
        ModelCandidateApplicability::Unknown(unknown)
    })
}

fn apply_conversion_proofs(report: &mut CallBindingReport, proofs: Vec<IndexedConversionProof>) {
    for (index, proof) in proofs {
        match proof {
            Ok(proof) => report.conversion_facts[index].establish(proof),
            Err(reason) => {
                report.conversion_facts[index].result = Err(reason);
                report.conversion_facts[index].completeness =
                    ConversionCompleteness::Unknown(reason);
            }
        }
    }
}

/// Owned selected declaration evidence retained for one query snapshot.
#[derive(Clone)]
pub struct ConversionDeclaration {
    pub unit: CodeUnit,
    pub parsed: Arc<ConversionSource>,
    pub range: std::ops::Range<usize>,
}

/// Structured inputs that make nongeneric method selection equivalent inside
/// one lexical scope. Reference mutability and depth remain part of the key.
pub struct RustMethodConversionInput<'a> {
    pub receiver: &'a RustConversionType,
    pub scope: std::ops::Range<usize>,
    pub member: &'a str,
    pub arity: usize,
    pub depth: usize,
}

#[derive(Clone, Hash, PartialEq, Eq)]
struct RustMethodConversionKey {
    file: ProjectFile,
    receiver: StableDigest,
    models: StableDigest,
    scope: std::ops::Range<usize>,
    member: Box<str>,
    arity: usize,
    depth: usize,
}

/// A modeled result's call site (file and byte range), receiver type digest
/// member name and proof depth. Depth binds the deterministic type-work
/// allowance; a shallow proof cannot hide a deeper request's budget stop.
/// This tuple exists only in the query provider's in-memory memo.
type RustModeledResultKey = (
    ProjectFile,
    std::ops::Range<usize>,
    StableDigest,
    String,
    usize,
    StableDigest,
);

type RustExpressionTypeKey = (ProjectFile, usize, usize, usize, StableDigest);

/// One indexed source/tree per file, scoped to the caller's query snapshot.
pub struct CallConversionCache {
    #[cfg(any(test, feature = "test-support"))]
    lexical_work: std::sync::Mutex<crate::analyzer::lexical_definitions::LexicalIndexWork>,
    #[cfg(any(test, feature = "test-support"))]
    source_acquisitions: std::sync::atomic::AtomicUsize,
    rust_modeled_results: super::common::QueryReadMemo<
        RustModeledResultKey,
        Result<RustConversionType, ConversionUnknown>,
    >,
    rust_methods: super::common::QueryReadMemo<
        RustMethodConversionKey,
        Result<ConversionDeclaration, ConversionUnknown>,
    >,
    rust_expressions: super::common::QueryReadMemo<
        RustExpressionTypeKey,
        Result<RustConversionType, ConversionUnknown>,
    >,
    declarations: super::common::QueryReadMemo<
        (ProjectFile, usize, usize),
        Result<ConversionDeclaration, ConversionUnknown>,
    >,
    scope_support: super::common::QueryReadMemo<
        (ProjectFile, usize, usize, String),
        Result<(), ConversionUnknown>,
    >,
    prefilter_effects: super::common::QueryReadMemo<(ProjectFile, usize, usize), bool>,
    actual_effects: super::common::QueryReadMemo<(ProjectFile, usize, usize), bool>,
    sources: super::common::QueryReadMemo<ProjectFile, Option<Arc<ConversionSource>>>,
    shapes:
        super::common::QueryReadMemo<ProjectFile, HashMap<(usize, usize), Option<CallShapeReport>>>,
}

impl Default for CallConversionCache {
    fn default() -> Self {
        Self {
            rust_modeled_results: super::common::query_read_memo(),
            rust_methods: super::common::query_read_memo(),
            rust_expressions: super::common::query_read_memo(),
            declarations: super::common::query_read_memo(),
            scope_support: super::common::query_read_memo(),
            prefilter_effects: super::common::query_read_memo(),
            actual_effects: super::common::query_read_memo(),
            sources: super::common::query_read_memo(),
            #[cfg(any(test, feature = "test-support"))]
            lexical_work: Default::default(),
            #[cfg(any(test, feature = "test-support"))]
            source_acquisitions: Default::default(),
            shapes: super::common::query_read_memo(),
        }
    }
}

fn retain_conversion_result<T>(
    analyzer: &dyn IAnalyzer,
    value: &Result<T, ConversionUnknown>,
) -> bool {
    let stable = !matches!(
        value,
        Err(ConversionUnknown::Cancelled | ConversionUnknown::BudgetExhausted)
    ) && !conversion_request_cancelled(analyzer);
    if !stable {
        analyzer.refuse_read_reuse();
    }
    stable
}

fn conversion_request_cancelled(analyzer: &dyn IAnalyzer) -> bool {
    let cancelled = analyzer
        .active_query_cancellation()
        .as_ref()
        .is_some_and(crate::CancellationToken::is_cancelled);
    if cancelled {
        analyzer.refuse_read_reuse();
    }
    cancelled
}

// These memos replay their captured reads; they do not revalidate them on a
// hit. Bind model-dependent Rust proofs to the current snapshot as well as
// source coordinates, even when an alias erases to a primitive or source type.
fn rust_conversion_model_set(analyzer: &dyn IAnalyzer) -> StableDigest {
    let snapshot = analyzer.active_semantic_model_snapshot();
    crate::analyzer::i_analyzer::current_model_set_digest(
        snapshot
            .as_ref()
            .map(|snapshot| snapshot.active_models().active_model_set_hash()),
    )
}

impl CallConversionCache {
    /// Cache operation-bound modeled results and replay all reads on a hit.
    /// The key includes the call site: member selection depends on the
    /// call's arity and on the traits visible at it, so two calls on the
    /// same receiver type and member name may select different methods.
    #[allow(clippy::too_many_arguments)]
    pub fn rust_modeled_result(
        &self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        call: std::ops::Range<usize>,
        receiver: &RustConversionType,
        member: &str,
        depth: usize,
        prove: impl FnOnce() -> Result<RustConversionType, ConversionUnknown>,
    ) -> Result<RustConversionType, ConversionUnknown> {
        if conversion_request_cancelled(analyzer) {
            return Err(ConversionUnknown::Cancelled);
        }
        let key = (
            file.clone(),
            call,
            receiver.digest(),
            member.to_owned(),
            depth,
            rust_conversion_model_set(analyzer),
        );
        let value = super::common::query_reentrant_memo_value(
            &self.rust_modeled_results,
            analyzer,
            &key,
            prove,
            |value| retain_conversion_result(analyzer, value),
        );
        if conversion_request_cancelled(analyzer) {
            return Err(ConversionUnknown::Cancelled);
        }
        (*value).clone()
    }

    /// Share selected method and owner proofs across equivalent applications;
    /// replay the fill's complete native lookup/type read receipt on every hit.
    pub fn rust_method_declaration(
        &self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        input: RustMethodConversionInput<'_>,
        resolve: impl FnOnce() -> Result<ConversionDeclaration, ConversionUnknown>,
    ) -> Result<ConversionDeclaration, ConversionUnknown> {
        if conversion_request_cancelled(analyzer) {
            return Err(ConversionUnknown::Cancelled);
        }
        let key = RustMethodConversionKey {
            file: file.clone(),
            receiver: input.receiver.digest(),
            models: rust_conversion_model_set(analyzer),
            scope: input.scope,
            member: input.member.into(),
            arity: input.arity,
            depth: input.depth,
        };
        let value = super::common::query_reentrant_memo_value(
            &self.rust_methods,
            analyzer,
            &key,
            resolve,
            |value| retain_conversion_result(analyzer, value),
        );
        if conversion_request_cancelled(analyzer) {
            return Err(ConversionUnknown::Cancelled);
        }
        (*value).clone()
    }

    /// Expression proofs are request-local and retain their transitive reads.
    pub fn rust_expression_type(
        &self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        range: std::ops::Range<usize>,
        depth: usize,
        prove: impl FnOnce() -> Result<RustConversionType, ConversionUnknown>,
    ) -> Result<RustConversionType, ConversionUnknown> {
        if conversion_request_cancelled(analyzer) {
            return Err(ConversionUnknown::Cancelled);
        }
        let key = (
            file.clone(),
            range.start,
            range.end,
            depth,
            rust_conversion_model_set(analyzer),
        );
        let value = super::common::query_reentrant_memo_value(
            &self.rust_expressions,
            analyzer,
            &key,
            prove,
            |value| retain_conversion_result(analyzer, value),
        );
        if conversion_request_cancelled(analyzer) {
            return Err(ConversionUnknown::Cancelled);
        }
        (*value).clone()
    }

    /// Resolve once and replay all selected lookup reads in every later capture.
    pub fn declaration(
        &self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        range: std::ops::Range<usize>,
        resolve: impl FnOnce() -> Result<ConversionDeclaration, ConversionUnknown>,
    ) -> Result<ConversionDeclaration, ConversionUnknown> {
        let key = (file.clone(), range.start, range.end);
        let value = super::common::query_memo_value(&self.declarations, analyzer, &key, resolve);
        (*value).clone()
    }

    /// Retain one language-owned scope proof and replay its transitive reads.
    pub fn source_scope_support(
        &self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        scope: tree_sitter::Node<'_>,
        prove: impl FnOnce() -> Result<(), ConversionUnknown>,
    ) -> Result<(), ConversionUnknown> {
        *super::common::query_memo_value(
            &self.scope_support,
            analyzer,
            &(
                file.clone(),
                scope.start_byte(),
                scope.end_byte(),
                scope.kind().to_owned(),
            ),
            prove,
        )
    }

    /// Exact call shapes, with fill reads replayed into every consumer.
    pub(crate) fn shape(
        &self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        range: &crate::analyzer::Range,
    ) -> Option<CallShapeReport> {
        let shapes = super::common::query_memo_value(&self.shapes, analyzer, file, || {
            let mut shapes = HashMap::default();
            if let Some(facts) = analyzer
                .structural_fact_providers()
                .into_iter()
                .find_map(|provider| provider.structural_facts(file))
            {
                for shape in
                    super::call_shape::call_shapes_in_file(&facts, file, facts.nodes().len())
                {
                    let key = (shape.outcome.range.start_byte, shape.outcome.range.end_byte);
                    match shapes.entry(key) {
                        std::collections::hash_map::Entry::Vacant(entry) => {
                            entry.insert(Some(shape));
                        }
                        std::collections::hash_map::Entry::Occupied(mut entry) => {
                            entry.insert(None);
                        }
                    }
                }
            }
            shapes
        });
        shapes
            .get(&(range.start_byte, range.end_byte))
            .cloned()
            .flatten()
    }

    /// Ask the language hook about each actual before resolving a formal.
    pub(crate) fn actuals_may_run_user_code(
        &self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        range: &crate::analyzer::Range,
        budget: &mut crate::analyzer::semantic::SemanticBudget,
    ) -> Result<bool, crate::analyzer::semantic::SemanticBudgetExceeded> {
        let Some(shape) = self.shape(analyzer, file, range) else {
            return Ok(true);
        };
        // call_shape omits argument rows for unreadable shapes. Unknown
        // arguments must not become a proof that zero conversions run.
        if !shape.outcome.coverage.is_exact() {
            return Ok(true);
        }
        let Some(source) = self.source(analyzer, file) else {
            return Ok(true);
        };
        source.charge_parse(budget)?;
        if let Some(facts) = analyzer
            .structural_fact_providers()
            .into_iter()
            .find_map(|provider| provider.structural_facts(file))
        {
            source.charge_shape(facts.nodes().len(), budget)?;
        }
        budget.charge_work(crate::analyzer::semantic::SemanticWork {
            nested_entries: shape.arguments.len(),
            ..Default::default()
        });
        Ok(*super::common::query_memo_value(
            &self.prefilter_effects,
            analyzer,
            &(file.clone(), range.start_byte, range.end_byte),
            || {
                shape
                    .arguments
                    .iter()
                    .any(|argument| self.actual_may_run_user_code(analyzer, file, &argument.range))
            },
        ))
    }

    pub(crate) fn actual_may_run_user_code(
        &self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        range: &crate::analyzer::Range,
    ) -> bool {
        *super::common::query_memo_value(
            &self.actual_effects,
            analyzer,
            &(file.clone(), range.start_byte, range.end_byte),
            || {
                let Some(source) = self.source(analyzer, file) else {
                    return true;
                };
                let actual = source
                    .tree
                    .root_node()
                    .named_descendant_for_byte_range(range.start_byte, range.end_byte)
                    .filter(|node| {
                        node.byte_range() == (range.start_byte..range.end_byte)
                            && !node.has_error()
                            && !node.is_missing()
                    });
                language_support_for_hook(
                    language_for_file(file),
                    "call_argument_conversion_prover",
                )
                .and_then(LanguageSupport::call_argument_conversion_prover)
                .is_some_and(|prover| {
                    prover.unknown_conversion_may_run_user_code(
                        analyzer,
                        self,
                        actual.map(|node| ConversionSyntax {
                            file,
                            node,
                            source: &source.source,
                        }),
                        None,
                    )
                })
            },
        )
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn lexical_work(
        &self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
    ) -> crate::analyzer::lexical_definitions::LexicalIndexWork {
        let _ = (analyzer, file);
        *self.lexical_work.lock().unwrap()
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn source_acquisitions(&self) -> usize {
        self.source_acquisitions
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn source(
        &self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
    ) -> Option<Arc<ConversionSource>> {
        #[cfg(any(test, feature = "test-support"))]
        self.source_acquisitions
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let value = super::common::query_memo_value(&self.sources, analyzer, file, || {
            let source = analyzer.indexed_source(file)?;
            let tree = parse_tree_for_language(file, language_for_file(file), &source)?;
            Some(Arc::new(ConversionSource::new(
                file,
                Arc::from(source),
                tree,
            )))
        });
        (*value).clone()
    }

    /// Resolve conversion typing for a selected source signature and project
    /// only an exact call/target/signature/actual/formal join into binding rows.
    pub fn populate(
        &self,
        analyzer: &dyn IAnalyzer,
        report: &mut CallBindingReport,
        signature: Option<&str>,
    ) {
        self.populate_with_context(
            &CallConversionContext::reference(self),
            analyzer,
            report,
            signature,
        );
    }

    #[doc(hidden)]
    pub fn indexed_context(
        &self,
        indexes: crate::analyzer::lexical_definitions::LexicalIndexCache,
    ) -> CallConversionContext<'_> {
        CallConversionContext {
            cache: self,
            indexes: Some(indexes),
        }
    }

    #[doc(hidden)]
    pub fn populate_with_context(
        &self,
        context: &CallConversionContext<'_>,
        analyzer: &dyn IAnalyzer,
        report: &mut CallBindingReport,
        signature: Option<&str>,
    ) {
        let language = language_for_file(&report.file);
        let prerequisite =
            match language_support_for_hook(language, "call_argument_conversion_prover")
                .and_then(LanguageSupport::call_argument_conversion_prover)
            {
                Some(prover) => self.prove(context, analyzer, report, signature, language, prover),
                None => Err(ConversionUnknown::UnsupportedLanguage),
            };
        report.conversion_facts = report
            .rows
            .iter()
            .map(|row| {
                CallArgumentConversion::unknown(
                    row,
                    report.target.as_ref(),
                    signature,
                    prerequisite
                        .as_ref()
                        .err()
                        .copied()
                        .unwrap_or(ConversionUnknown::AmbiguousBinding),
                )
            })
            .collect();
        if let Ok(proofs) = prerequisite {
            apply_conversion_proofs(report, proofs);
        }
        project_conversion_facts(report, signature, None);
    }

    /// Whether the conversion at `row`, left unknown by `populate`, may run
    /// user code, as the call language's prover reads the actual and the
    /// selected formal. A side that cannot be read is passed as `None`.
    pub fn unknown_conversion_may_run_user_code(
        &self,
        analyzer: &dyn IAnalyzer,
        report: &CallBindingReport,
        row: &CallBindingRow,
    ) -> bool {
        let language = language_for_file(&report.file);
        let Some(prover) = language_support_for_hook(language, "call_argument_conversion_prover")
            .and_then(LanguageSupport::call_argument_conversion_prover)
        else {
            return false;
        };
        let source = self.source(analyzer, &report.file);
        let actual = source.as_deref().and_then(|source| {
            let node = exact_argument_expression(source, row).ok()?;
            Some(ConversionSyntax {
                file: &report.file,
                node,
                source: &source.source,
            })
        });
        let formal_source = report
            .target
            .as_ref()
            .and_then(|target| Some((target, self.source(analyzer, target.source())?)));
        let formal = formal_source.as_ref().and_then(|(target, formal_source)| {
            let formal_index = exact_positional_formal_index(row).ok()?;
            let ranges = analyzer.ranges_of(target);
            let [range] = ranges.as_slice() else {
                return None;
            };
            let owner = parameter_owner_for_range(
                language_for_file(target.source()),
                formal_source.tree.root_node(),
                range,
            )?;
            let slots = formal_parameter_slots_for_owner_with_nodes(
                language_for_file(target.source()),
                owner,
                &formal_source.source,
            )?;
            let (_, node) = slots
                .into_iter()
                .filter(|(slot, _)| !slot.receiver)
                .nth(formal_index)?;
            Some(ConversionSyntax {
                file: target.source(),
                node,
                source: &formal_source.source,
            })
        });
        prover.unknown_conversion_may_run_user_code(analyzer, self, actual, formal)
    }

    #[allow(clippy::too_many_arguments)]
    fn prove(
        &self,
        context: &CallConversionContext<'_>,
        analyzer: &dyn IAnalyzer,
        report: &CallBindingReport,
        signature: Option<&str>,
        language: Language,
        prover: &dyn CallArgumentConversionProver,
    ) -> Result<Vec<IndexedConversionProof>, ConversionUnknown> {
        signature.ok_or(ConversionUnknown::UnresolvedSignature)?;
        let target = report
            .target
            .as_ref()
            .ok_or(ConversionUnknown::UnresolvedSignature)?;
        let metadata = analyzer.signature_metadata(target);
        let [metadata] = metadata.as_slice() else {
            return Err(ConversionUnknown::UnresolvedSignature);
        };
        if !metadata.type_parameters().is_empty() {
            return Err(ConversionUnknown::GenericSubstitution);
        }
        let source = self
            .source(analyzer, &report.file)
            .ok_or(ConversionUnknown::UnresolvedSourceType)?;
        let formal_source = self
            .source(analyzer, target.source())
            .ok_or(ConversionUnknown::UnresolvedTargetType)?;
        let ranges = analyzer.ranges_of(target);
        let [range] = ranges.as_slice() else {
            return Err(ConversionUnknown::UnresolvedSignature);
        };
        let owner = parameter_owner_for_range(language, formal_source.tree.root_node(), range)
            .ok_or(ConversionUnknown::UnresolvedSignature)?;
        // Generic owners require substitution even when the method itself is
        // nongeneric. The bounded adapters deliberately do not erase a type.
        let mut enclosing = Some(owner);
        while let Some(node) = enclosing {
            if node.child_by_field_name("type_parameters").is_some() {
                return Err(ConversionUnknown::GenericSubstitution);
            }
            enclosing = node.parent();
        }
        prover.validate_owner(owner)?;
        let slots =
            formal_parameter_slots_for_owner_with_nodes(language, owner, &formal_source.source)
                .ok_or(ConversionUnknown::UnresolvedTargetType)?;
        let ordinary: Vec<_> = slots.iter().filter(|(slot, _)| !slot.receiver).collect();
        let mut proofs = Vec::new();
        for (index, row) in report.rows.iter().enumerate() {
            if !is_explicit_conversion_row(row) {
                continue;
            }
            let proof = (|| {
                let formal_index = exact_positional_formal_index(row)?;
                let (slot, formal) = ordinary
                    .get(formal_index)
                    .ok_or(ConversionUnknown::UnresolvedTargetType)?;
                if slot.variadic.is_some() {
                    return Err(ConversionUnknown::UnsupportedConversion);
                }
                let actual = exact_argument_expression(&source, row)?;
                if formal.has_error() || formal.is_missing() {
                    return Err(ConversionUnknown::UnsupportedExpression);
                }
                prover.prove_argument(
                    analyzer,
                    context,
                    &report.file,
                    actual,
                    &source.source,
                    target.source(),
                    *formal,
                    &formal_source.source,
                )
            })();
            proofs.push((index, proof));
        }
        // A type-compatible pair cannot borrow a signature whose applicability
        // is still unestablished at another actual.
        let missing_formal = ordinary.iter().enumerate().any(|(index, _)| {
            !report
                .rows
                .iter()
                .any(|row| row.formal_index == Some(index) && row.argument_id.is_some())
        });
        if prover.requires_complete_signature_for_argument_proofs()
            && (missing_formal
                || proofs.iter().any(|(_, proof)| proof.is_err())
                || report
                    .rows
                    .iter()
                    .any(|row| row.terminal || row.mapping != CallBindingMapping::Exact))
        {
            for (_, proof) in &mut proofs {
                if proof.is_ok() {
                    *proof = Err(ConversionUnknown::SignatureApplicability);
                }
            }
        }
        Ok(proofs)
    }

    /// Select the model overload the call invokes: the one candidate that is
    /// not proven inapplicable, or the applicable candidate that the
    /// language's overload rules prove most specific. No such overload and
    /// several undecidable ones are distinct typed failures.
    pub fn select_model_signature(
        &self,
        analyzer: &dyn IAnalyzer,
        shape: &CallShapeReport,
        caller_source: Option<(&ProjectFile, &str)>,
        candidates: &[(String, Signature)],
    ) -> Result<Option<(String, Signature)>, ConversionUnknown> {
        let cancellation = analyzer.active_query_cancellation();
        let is_cancelled = || {
            cancellation
                .as_ref()
                .is_some_and(crate::CancellationToken::is_cancelled)
        };
        if is_cancelled() {
            return Err(ConversionUnknown::Cancelled);
        }
        let prover = model_conversion_prover(&shape.outcome.file)?;
        let source = self.model_call_source(analyzer, shape, caller_source)?;
        let written = written_model_actuals(&source, shape, &is_cancelled)?;

        if let Some(selected) = prover.select_model_invocation(
            analyzer,
            &shape.outcome.file,
            &written,
            &source.source,
            &candidates
                .iter()
                .map(|(_, signature)| signature.clone())
                .collect::<Vec<_>>(),
        ) {
            return selected.map(|(index, _)| Some(candidates[index].clone()));
        }
        let mut applicable = Vec::new();
        let mut exact = Vec::new();
        let mut undecided = Vec::new();
        let mut failures = Vec::new();
        for (model_id, signature) in candidates {
            match model_candidate_applicability(
                prover,
                analyzer,
                &shape.outcome.file,
                &source.source,
                &written,
                signature,
                &is_cancelled,
            )? {
                ModelCandidateApplicability::Applicable { exact: is_exact } => {
                    if is_exact {
                        exact.push((model_id, signature));
                    }
                    applicable.push((model_id.clone(), signature.clone()));
                }
                ModelCandidateApplicability::LayoutMismatch
                | ModelCandidateApplicability::Rejected => {}
                ModelCandidateApplicability::Unknown(unknown) => {
                    failures.extend(unknown);
                    undecided.push((model_id, signature));
                }
            }
        }
        if is_cancelled() {
            return Err(ConversionUnknown::Cancelled);
        }
        // Where an exact match beats every other member, the one candidate
        // whose actuals all have exactly its formal types is the overload the
        // code calls, as Ov(Stream) is for a Stream actual beside Ov(byte[])
        // (#8296). Two exact candidates differ only in what the positional
        // types cannot see (optional or expanded formals), so they fall
        // through and stay ambiguous.
        if let [(model_id, signature)] = exact.as_slice()
            && prover.exact_match_is_best_member()
        {
            return Ok(Some(((*model_id).clone(), (*signature).clone())));
        }
        // As for a unique layout match (#9981), only a proven rejection removes
        // an overload of a complete family: when every other candidate is
        // rejected, the one undecided candidate is the overload the code calls,
        // and its conversion facts stay typed unknown.
        if let ([], [(model_id, signature)]) = (applicable.as_slice(), undecided.as_slice()) {
            return Ok(Some(((*model_id).clone(), (*signature).clone())));
        }
        // Several overloads can accept the actuals, as print(String) and
        // print(Object) both accept a String, and a peer's applicability can
        // stay undecided, as print(Object) for a char[] actual. The overload
        // the code calls is then the one applicable overload strictly more
        // specific than every other candidate that was not rejected: whether
        // or not an undecided peer applies, it cannot win against it.
        if applicable.len() > 1 || (applicable.len() == 1 && !failures.is_empty()) {
            let arity = u32::try_from(written.len()).expect("written call arity must fit u32");
            let most_specific = applicable
                .iter()
                .enumerate()
                .find(|(index, (_, specific))| {
                    applicable
                        .iter()
                        .enumerate()
                        .filter(|(other_index, _)| other_index != index)
                        .map(|(_, (_, other))| other)
                        .chain(undecided.iter().map(|(_, other)| *other))
                        .all(|other| {
                            prover.model_signature_more_specific(
                                analyzer,
                                &shape.outcome.file,
                                arity,
                                specific,
                                other,
                            )
                        })
                });
            if let Some((_, selected)) = most_specific {
                return Ok(Some(selected.clone()));
            }
            if is_cancelled() {
                return Err(ConversionUnknown::Cancelled);
            }
        }
        match applicable.as_slice() {
            [_, _, ..] => Err(ConversionUnknown::AmbiguousBinding),
            [(model_id, signature)] if failures.is_empty() => {
                Ok(Some((model_id.clone(), signature.clone())))
            }
            _ if failures.windows(2).all(|pair| pair[0] == pair[1]) && !failures.is_empty() => {
                Err(failures[0])
            }
            _ => Err(ConversionUnknown::SignatureApplicability),
        }
    }

    /// Whether some written positional actual provably cannot convert to its
    /// formal in the one model member whose layout matches the call. A binder
    /// that found a unique layout-compatible member must not attribute such a
    /// call to it: the code calls an overload the model never declared
    /// (#9981). Only a proven rejection counts; an actual whose type or
    /// conversion is unknown keeps the binding and its conversion facts stay
    /// typed unknown, as they do for every other unique model binding.
    /// Returns an error only when the query was cancelled.
    pub fn model_signature_rejects_call(
        &self,
        analyzer: &dyn IAnalyzer,
        shape: &CallShapeReport,
        caller_source: Option<(&ProjectFile, &str)>,
        signature: &Signature,
    ) -> Result<bool, ConversionUnknown> {
        let cancellation = analyzer.active_query_cancellation();
        let is_cancelled = || {
            cancellation
                .as_ref()
                .is_some_and(crate::CancellationToken::is_cancelled)
        };
        if is_cancelled() {
            return Err(ConversionUnknown::Cancelled);
        }
        // Without a prover, a source tree or exact written actuals nothing can
        // be proven inapplicable, so the unique binding stands.
        let Ok(prover) = model_conversion_prover(&shape.outcome.file) else {
            return Ok(false);
        };
        let Ok(source) = self.model_call_source(analyzer, shape, caller_source) else {
            return Ok(false);
        };
        let written = match written_model_actuals(&source, shape, &is_cancelled) {
            Ok(written) => written,
            Err(reason @ ConversionUnknown::Cancelled) => return Err(reason),
            Err(_) => return Ok(false),
        };
        let applicability = model_candidate_applicability(
            prover,
            analyzer,
            &shape.outcome.file,
            &source.source,
            &written,
            signature,
            &is_cancelled,
        );
        // A budget stop proves nothing: the binding stands and its conversion
        // facts report the exhausted budget.
        match applicability {
            Ok(applicability) => Ok(matches!(
                applicability,
                ModelCandidateApplicability::Rejected
            )),
            Err(reason @ ConversionUnknown::Cancelled) => Err(reason),
            Err(_) => Ok(false),
        }
    }

    fn model_call_source(
        &self,
        analyzer: &dyn IAnalyzer,
        shape: &CallShapeReport,
        caller_source: Option<(&ProjectFile, &str)>,
    ) -> Result<Arc<ConversionSource>, ConversionUnknown> {
        if let Some(source) = self.source(analyzer, &shape.outcome.file) {
            return Ok(source);
        }
        let (file, source) = caller_source
            .filter(|(file, _)| *file == &shape.outcome.file)
            .ok_or(ConversionUnknown::UnresolvedSourceType)?;
        let tree = parse_tree_for_language(file, language_for_file(file), source)
            .ok_or(ConversionUnknown::UnresolvedSourceType)?;
        Ok(Arc::new(ConversionSource::new(
            file,
            Arc::from(source),
            tree,
        )))
    }

    /// Populate conversions for the exact model target/signature/actual/formal
    /// join selected by the model call binder.
    pub fn populate_model_signature(
        &self,
        analyzer: &dyn IAnalyzer,
        report: &mut CallBindingReport,
        model_target_id: &str,
        signature_id: &str,
        signature: &Signature,
    ) {
        let language = language_for_file(&report.file);
        let prerequisite = language_support_for_hook(language, "call_argument_conversion_prover")
            .and_then(LanguageSupport::call_argument_conversion_prover)
            .ok_or(ConversionUnknown::UnsupportedLanguage)
            .and_then(|prover| self.prove_model(analyzer, report, prover, signature));
        report.conversion_facts = report
            .rows
            .iter()
            .map(|row| {
                CallArgumentConversion::unknown_model(
                    row,
                    model_target_id,
                    Some(signature_id),
                    prerequisite
                        .as_ref()
                        .err()
                        .copied()
                        .unwrap_or(ConversionUnknown::AmbiguousBinding),
                )
            })
            .collect();
        if let Ok(proofs) = prerequisite {
            apply_conversion_proofs(report, proofs);
        }
        project_conversion_facts(report, Some(signature_id), Some(model_target_id));
    }

    fn prove_model(
        &self,
        analyzer: &dyn IAnalyzer,
        report: &CallBindingReport,
        prover: &dyn CallArgumentConversionProver,
        signature: &Signature,
    ) -> Result<Vec<IndexedConversionProof>, ConversionUnknown> {
        let source = self
            .source(analyzer, &report.file)
            .ok_or(ConversionUnknown::UnresolvedSourceType)?;
        let invocation_formals = if signature.parameters.iter().any(|formal| formal.variadic) {
            let actuals = report
                .rows
                .iter()
                .filter(|row| is_explicit_conversion_row(row))
                .map(|row| exact_argument_expression(&source, row))
                .collect::<Result<Vec<_>, _>>()?;
            match prover.select_model_invocation(
                analyzer,
                &report.file,
                &actuals,
                &source.source,
                std::slice::from_ref(signature),
            ) {
                Some(result) => Some(result?.1),
                None => return Err(ConversionUnknown::UnsupportedConversion),
            }
        } else {
            None
        };
        let mut actual_ordinal = 0;
        let mut proofs = Vec::new();
        for (index, row) in report.rows.iter().enumerate() {
            if !is_explicit_conversion_row(row) {
                continue;
            }
            let proof = (|| {
                let formal_index = exact_positional_formal_index(row)?;
                let formal = signature
                    .parameters
                    .get(formal_index)
                    .ok_or(ConversionUnknown::UnresolvedTargetType)?;
                let formal_type = match &invocation_formals {
                    Some(formals) => formals
                        .get(actual_ordinal)
                        .ok_or(ConversionUnknown::UnresolvedTargetType)?,
                    None => &formal.r#type,
                };
                let actual = exact_argument_expression(&source, row)?;
                prover.prove_model_argument(
                    analyzer,
                    &report.file,
                    actual,
                    &source.source,
                    formal_type,
                )
            })();
            actual_ordinal += 1;
            proofs.push((index, proof));
        }
        if prover.requires_complete_signature_for_argument_proofs()
            && (proofs.iter().any(|(_, proof)| proof.is_err())
                || report
                    .rows
                    .iter()
                    .any(|row| row.terminal || row.mapping != CallBindingMapping::Exact))
        {
            for (_, proof) in &mut proofs {
                if proof.is_ok() {
                    *proof = Err(ConversionUnknown::SignatureApplicability);
                }
            }
        }
        Ok(proofs)
    }
}

/// Presentation is an exact identity join, independent of fact ordering. A
/// fact for another signature, target, actual or formal cannot label or explain
/// this row; an ordinary actual with no matching fact gets typed ambiguous
/// conversion evidence instead. Receiver, implicit and absent-actual rows do
/// not have a conversion field to explain.
pub fn project_conversion_facts(
    report: &mut CallBindingReport,
    signature: Option<&str>,
    expected_model_target: Option<&str>,
) {
    let mut by_binding = HashMap::default();
    for fact in &report.conversion_facts {
        // A source fact joins only its own report target; a model fact joins
        // only the exact unmaterialized model target the binder selected.
        let target_kind_matches = match (expected_model_target, fact.model_target_id.as_deref()) {
            (Some(expected), Some(actual)) => {
                actual == expected && fact.target.is_none() && report.target.is_none()
            }
            (None, None) => fact.target.is_some() && fact.target == report.target,
            _ => false,
        };
        if !target_kind_matches || fact.selected_signature.as_deref() != signature {
            continue;
        }
        if signature.is_none() {
            assert!(
                fact.selected_signature.is_none(),
                "a signatureless model conversion cannot join a signatureless query",
            );
        }
        let previous = by_binding.insert(
            (
                fact.site_id.as_str(),
                fact.argument_id.as_deref(),
                fact.formal_index,
            ),
            fact,
        );
        assert!(
            previous.is_none(),
            "one conversion result per exact actual/formal pair"
        );
    }
    for row in &mut report.rows {
        let fact = by_binding.get(&(
            row.site_id.as_str(),
            row.argument_id.as_deref(),
            row.formal_index,
        ));
        row.conversion = fact
            .and_then(|fact| fact.result.as_ref().ok())
            .map(|proof| proof.kind.label().to_owned());
        row.conversion_reason = if row.argument_id.is_some()
            && !matches!(
                row.binding_kind,
                Some(CallBindingKind::Receiver | CallBindingKind::Implicit)
            ) {
            match fact {
                Some(fact) => fact.result.as_ref().err().copied(),
                None => Some(ConversionUnknown::AmbiguousBinding),
            }
        } else {
            None
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::usages::call_binding::CallBindingCoverage;
    use crate::analyzer::{CodeUnitType, Range};
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    fn projected_types_preserve_complete_identity_and_digest() {
        let complete = RustConversionType::Model {
            model_set: "active-set".to_owned(),
            symbol: "model::Pair".to_owned(),
            arguments: vec![
                RustConversionType::Reference {
                    mutable: true,
                    referent: Box::new(RustConversionType::Array {
                        element: Box::new(RustConversionType::Primitive(RustPrimitive::U8)),
                        length: 4,
                    }),
                },
                RustConversionType::Tuple(vec![
                    RustConversionType::Slice {
                        element: Box::new(RustConversionType::Primitive(RustPrimitive::Str)),
                    },
                    RustConversionType::Unit,
                ]),
            ],
        };
        assert_eq!(
            complete.digest().to_string(),
            "16eae00890cf22d07e56a9bbc35a282478a9f805222f02fa05c0b1aba64fa9c4"
        );
        let roundtrip = RustProjectedType::from(complete.clone())
            .into_complete()
            .expect("no unknown components");
        assert_eq!(complete, roundtrip);
        assert_eq!(complete.digest(), roundtrip.digest());
        let declaration = CodeUnit::new(
            ProjectFile::new(std::env::temp_dir(), "carrier.rs"),
            CodeUnitType::Class,
            "",
            "Carrier",
        );
        for complete in [
            RustConversionType::Declaration(declaration.clone()),
            RustConversionType::AppliedDeclaration {
                declaration,
                arguments: vec![RustConversionType::Primitive(RustPrimitive::U8)],
            },
        ] {
            assert_eq!(
                RustProjectedType::from(complete.clone()).into_complete(),
                Ok(complete)
            );
        }
        let partial = RustProjectedType::Model {
            model_set: "active-set".to_owned(),
            symbol: "model::Pair".to_owned(),
            arguments: vec![RustProjectedType::Unknown(
                ConversionUnknown::GenericSubstitution,
            )],
        };
        assert_eq!(
            partial.into_complete(),
            Err(ConversionUnknown::GenericSubstitution)
        );
    }

    #[test]
    #[hardwon("#10770: stopped Rust conversion proofs were retained by query-local memos")]
    fn rust_proof_memos_do_not_retain_budget_or_cancellation_stops() {
        use crate::analyzer::MultiAnalyzer;
        let analyzer = MultiAnalyzer::default();
        let file = ProjectFile::new(std::env::temp_dir(), "stopped-conversion.rs");
        for reason in [
            ConversionUnknown::BudgetExhausted,
            ConversionUnknown::Cancelled,
        ] {
            let cache = CallConversionCache::default();
            assert_eq!(
                cache.rust_expression_type(&analyzer, &file, 0..1, 0, || Err(reason)),
                Err(reason)
            );
            assert_eq!(
                cache.rust_expression_type(&analyzer, &file, 0..1, 0, || Ok(
                    RustConversionType::Unit
                )),
                Ok(RustConversionType::Unit)
            );
            assert_eq!(
                cache.rust_expression_type(&analyzer, &file, 0..1, 0, || panic!(
                    "complete result must be retained"
                )),
                Ok(RustConversionType::Unit)
            );
            let receiver = RustConversionType::Unit;
            assert_eq!(
                cache.rust_modeled_result(&analyzer, &file, 0..1, &receiver, "value", 0, || Err(
                    reason
                )),
                Err(reason)
            );
            assert_eq!(
                cache.rust_modeled_result(&analyzer, &file, 0..1, &receiver, "value", 0, || Ok(
                    RustConversionType::Unit
                )),
                Ok(RustConversionType::Unit)
            );
            let cancellation = crate::CancellationToken::new();
            let scope = crate::analyzer::i_analyzer::AnalyzerQueryScope::with_cancellation(
                &analyzer,
                &cancellation,
            );
            cancellation.cancel();
            assert_eq!(
                cache.rust_expression_type(&analyzer, &file, 0..1, 0, || panic!(
                    "cancelled hit must not build"
                )),
                Err(ConversionUnknown::Cancelled)
            );
            drop(scope);
            assert_eq!(
                cache.rust_expression_type(&analyzer, &file, 0..1, 0, || panic!(
                    "uncancelled complete result remains reusable"
                )),
                Ok(RustConversionType::Unit)
            );
        }
    }

    #[test]
    fn declaration_memo_hit_replays_reads() {
        use crate::analyzer::{MultiAnalyzer, ReadKey, capture_query_reads};
        let analyzer = MultiAnalyzer::default();
        let cache = CallConversionCache::default();
        let file = ProjectFile::new(std::env::temp_dir(), "conversion.rs");
        let key = ReadKey::Configuration(StableDigest::sha256(b"declaration input"));
        assert!(
            cache
                .declaration(&analyzer, &file, 0..1, || {
                    analyzer.record_read(key.clone());
                    Err(ConversionUnknown::UnresolvedTargetType)
                })
                .is_err()
        );
        let (_, reads) = capture_query_reads(&analyzer, || {
            assert!(
                cache
                    .declaration(&analyzer, &file, 0..1, || {
                        panic!("declaration memo hit rebuilt evidence")
                    })
                    .is_err()
            );
        });
        assert_eq!(reads.keys(), vec![key]);
    }

    fn report() -> CallBindingReport {
        let file = ProjectFile::new(std::env::temp_dir(), "Conversions.java");
        let target = CodeUnit::new(file.clone(), CodeUnitType::Function, "", "Conversions.take");
        let range = Range {
            start_byte: 0,
            end_byte: 1,
            start_line: 0,
            end_line: 0,
        };
        let rows: Vec<_> = (0..2)
            .map(|index| CallBindingRow {
                id: format!("binding-{index}"),
                site_id: "call".to_owned(),
                group_id: Some("group".to_owned()),
                argument_id: Some(format!("actual-{index}")),
                actual_index: Some(index),
                actual_name: None,
                formal_index: Some(index),
                formal_name: None,
                binding_kind: Some(CallBindingKind::Positional),
                mapping: CallBindingMapping::Exact,
                reason: None,
                conversion: None,
                conversion_reason: None,
                range,
                terminal: false,
            })
            .collect();
        let conversion_facts = rows
            .iter()
            .map(|row| {
                let mut fact = CallArgumentConversion::unknown(
                    row,
                    Some(&target),
                    Some("signature"),
                    ConversionUnknown::UnresolvedSourceType,
                );
                fact.establish(ArgumentTypeConversion {
                    hierarchy: None,
                    source: ResolvedConversionType::JavaPrimitive(JavaPrimitive::Int),
                    target: ResolvedConversionType::JavaPrimitive(if row.formal_index == Some(0) {
                        JavaPrimitive::Long
                    } else {
                        JavaPrimitive::Int
                    }),
                    kind: if row.formal_index == Some(0) {
                        ConversionKind::JavaPrimitiveWidening
                    } else {
                        ConversionKind::JavaIdentity
                    },
                });
                fact
            })
            .collect();
        CallBindingReport {
            file,
            site_id: "call".to_owned(),
            site_ast_id: "ast".to_owned(),
            range,
            target: Some(target),
            coverage: CallBindingCoverage::Exhaustive,
            actual_count: 2,
            bound_count: 2,
            rows,
            conversion_facts,
        }
    }

    #[test]
    fn projection_is_order_independent_and_reference_identity_has_no_transfer_barrier() {
        let mut expected = report();
        expected.conversion_facts[1] = CallArgumentConversion::unknown(
            &expected.rows[1],
            expected.target.as_ref(),
            Some("signature"),
            ConversionUnknown::UnsupportedExpression,
        );
        project_conversion_facts(&mut expected, Some("signature"), None);
        let mut reordered = report();
        reordered.conversion_facts[1] = CallArgumentConversion::unknown(
            &reordered.rows[1],
            reordered.target.as_ref(),
            Some("signature"),
            ConversionUnknown::UnsupportedExpression,
        );
        reordered.conversion_facts.reverse();
        project_conversion_facts(&mut reordered, Some("signature"), None);
        assert_eq!(expected.rows, reordered.rows);
        assert_eq!(
            expected.rows[1].conversion_reason,
            Some(ConversionUnknown::UnsupportedExpression)
        );
        assert_eq!(expected.rows[0].conversion_reason, None);
        let widening = expected.conversion_facts[0]
            .transfer()
            .expect("widening transfer");
        assert_eq!(
            widening.kind,
            TransferKind::Conversion {
                preservation: ValuePreservation::Preserving
            }
        );
        assert_eq!(
            Some(widening.operation),
            expected.conversion_facts[0].operation()
        );
        assert!(expected.conversion_facts[1].transfer().is_none());
        assert_ne!(
            expected.conversion_facts[0].operation(),
            expected.conversion_facts[1].operation()
        );
    }

    #[test]
    fn wrong_signature_target_actual_formal_and_site_cannot_borrow_a_conversion() {
        let original = report();
        for dimension in 0..5 {
            let mut changed = original.clone();
            let fact = &mut changed.conversion_facts[0];
            match dimension {
                0 => fact.selected_signature = Some("another-signature".to_owned()),
                1 => fact.target = None,
                2 => fact.argument_id = Some("another-actual".to_owned()),
                3 => fact.formal_index = Some(99),
                4 => fact.site_id = "another-call".to_owned(),
                _ => unreachable!(),
            }
            project_conversion_facts(&mut changed, Some("signature"), None);
            assert!(
                changed.rows[0].conversion.is_none(),
                "dimension {dimension}"
            );
            assert_eq!(
                changed.rows[0].conversion_reason,
                Some(ConversionUnknown::AmbiguousBinding),
                "dimension {dimension}"
            );
            assert_eq!(changed.rows[1].conversion.as_deref(), Some("java_identity"));
            assert_eq!(changed.rows[1].conversion_reason, None);
        }
    }

    #[test]
    #[hardwon(
        "2dc7a9b231a0: a modeled overload identity could borrow conversion evidence from a different model target"
    )]
    fn model_target_identity_is_disjoint_and_cannot_borrow_a_conversion() {
        let mut report = report();
        report.target = None;
        report.conversion_facts = report
            .rows
            .iter()
            .map(|row| {
                let mut fact = CallArgumentConversion::unknown_model(
                    row,
                    "member.run.string",
                    Some("signature"),
                    ConversionUnknown::UnresolvedSourceType,
                );
                fact.establish(ArgumentTypeConversion {
                    hierarchy: None,
                    source: ResolvedConversionType::JavaPrimitive(JavaPrimitive::Int),
                    target: ResolvedConversionType::JavaPrimitive(JavaPrimitive::Int),
                    kind: ConversionKind::JavaIdentity,
                });
                fact
            })
            .collect();

        project_conversion_facts(&mut report, Some("signature"), Some("member.run.array"));

        assert!(report.rows.iter().all(|row| row.conversion.is_none()));
        assert!(
            report
                .rows
                .iter()
                .all(|row| { row.conversion_reason == Some(ConversionUnknown::AmbiguousBinding) })
        );
    }

    #[test]
    fn conversion_reason_is_not_applicable_to_receiver_implicit_or_absent_actual_rows() {
        let mut receiver_report = report();
        receiver_report.rows[0].binding_kind = Some(CallBindingKind::Receiver);
        receiver_report.rows[1].argument_id = None;
        project_conversion_facts(&mut receiver_report, Some("signature"), None);
        assert_eq!(receiver_report.rows[0].conversion_reason, None);
        assert_eq!(receiver_report.rows[1].conversion_reason, None);

        let mut report = report();
        report.rows[0].binding_kind = Some(CallBindingKind::Implicit);
        project_conversion_facts(&mut report, Some("signature"), None);
        assert_eq!(report.rows[0].conversion_reason, None);
    }

    #[test]
    fn widening_that_rounds_values_does_not_claim_value_preservation() {
        let mut report = report();
        report.conversion_facts[0].establish(ArgumentTypeConversion {
            hierarchy: None,
            source: ResolvedConversionType::JavaPrimitive(JavaPrimitive::Int),
            target: ResolvedConversionType::JavaPrimitive(JavaPrimitive::Float),
            kind: ConversionKind::JavaPrimitiveWidening,
        });
        let witness = (1_i32 << 24) + 1;
        assert_ne!((witness as f32) as i32, witness);
        assert_eq!(
            report.conversion_facts[0]
                .transfer()
                .expect("widening")
                .kind,
            TransferKind::Conversion {
                preservation: ValuePreservation::Changing
            }
        );
    }
}
