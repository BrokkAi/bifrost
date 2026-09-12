//! Resolver-proven per-actual applicability facts (#2724).
//!
//! Binding and conversion completeness are separate: matching a formal slot
//! does not establish its type. This query-local relation consumes the selected
//! declaration and the shared formal layout. It never selects an overload.

use std::sync::Arc;

use crate::analyzer::common::language_for_file;
use crate::analyzer::languages::{LanguageSupport, language_support};
use crate::analyzer::lexical_definitions::{
    formal_parameter_slots_for_owner_with_nodes, parameter_owner_for_range,
};
use crate::analyzer::semantic::{
    LengthDelimitedDigest, StableDigest, TransferKind, TransferOperation, ValuePreservation,
    ValueTransfer,
};
use crate::analyzer::semantic_model::{Signature, TypeRef};
use crate::analyzer::usages::call_binding::{
    CallBindingKind, CallBindingMapping, CallBindingReport, CallBindingRow,
};
use crate::analyzer::usages::call_shape::CallShapeReport;
use crate::analyzer::usages::get_definition::parse_tree_for_language;
use crate::analyzer::{CodeUnit, IAnalyzer, Language, ProjectFile};
use crate::hash::HashMap;
use serde::{Deserialize, Serialize};

/// Identity of an external declaration proved by a language resolver.
///
/// This stores generic declaration evidence only. The language-specific producer owns
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
pub(crate) enum ExternalConversionProvenance {
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
    /// Construct an identity from resolver-owned artifact/model evidence.
    ///
    /// A semantic-pack declaration is not an exact identity without the active model-set
    /// digest, so construction refuses to produce one in that case.
    pub(crate) fn from_provenance(
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

    pub fn fqn(&self) -> &str {
        &self.fqn
    }

    pub(crate) fn digest(&self) -> StableDigest {
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

    pub(crate) fn declaration_is_class(&self) -> bool {
        self.declaration_is_class
    }
}

/// Language-owned call-argument conversion producer.
///
/// The shared relation owns exact call/signature/actual/formal joins and delegates only
/// owner applicability and one AST-backed actual/formal proof to the selected language.
pub(crate) trait CallArgumentConversionProver: Send + Sync {
    /// Validate applicability constraints owned by the formal language syntax.
    fn validate_owner(&self, _owner: tree_sitter::Node<'_>) -> Result<(), ConversionUnknown> {
        Ok(())
    }

    /// Prove one actual-to-formal pair from the language's resolver and AST evidence.
    #[allow(clippy::too_many_arguments)]
    fn prove_argument(
        &self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        actual: tree_sitter::Node<'_>,
        source: &str,
        formal_file: &ProjectFile,
        formal: tree_sitter::Node<'_>,
        formal_source: &str,
    ) -> Result<ArgumentTypeConversion, ConversionUnknown>;

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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JavaPrimitive {
    Boolean,
    Byte,
    Short,
    Char,
    Int,
    Long,
    Float,
    Double,
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

/// Structured Rust conversion types. The language producer bounds nesting
/// before construction; references describe conversion shape, not a proof of
/// borrow validity or region inference. Nominals retain resolved declarations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RustConversionType {
    Primitive(RustPrimitive),
    Declaration(CodeUnit),
    Reference { mutable: bool, referent: Box<Self> },
    Array { element: Box<Self>, length: u64 },
    Slice { element: Box<Self> },
    Tuple(Vec<Self>),
    Unit,
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
    TypeScriptPrimitive(TypeScriptPrimitive),
    Rust(RustConversionType),
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
    JavaBoxing,
    JavaUnboxing,
    TypeScriptIdentity,
    TypeScriptStructuralAssignability,
    RustIdentity,
    RustDeref,
    RustUnsizing,
    RustReborrow,
}

impl ConversionKind {
    pub const LABELS: &'static [&'static str] = &[
        "java_identity",
        "java_primitive_widening",
        "java_boxing",
        "java_unboxing",
        "typescript_identity",
        "typescript_structural_assignability",
        "rust_identity",
        "rust_deref",
        "rust_unsizing",
        "rust_reborrow",
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::JavaIdentity => "java_identity",
            Self::JavaPrimitiveWidening => "java_primitive_widening",
            Self::JavaBoxing => "java_boxing",
            Self::JavaUnboxing => "java_unboxing",
            Self::TypeScriptIdentity => "typescript_identity",
            Self::TypeScriptStructuralAssignability => "typescript_structural_assignability",
            Self::RustIdentity => "rust_identity",
            Self::RustDeref => "rust_deref",
            Self::RustUnsizing => "rust_unsizing",
            Self::RustReborrow => "rust_reborrow",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConversionUnknown {
    UnsupportedLanguage,
    UnresolvedSignature,
    UnresolvedSourceType,
    UnresolvedTargetType,
    AmbiguousBinding,
    GenericSubstitution,
    UnsupportedConversion,
    UnsupportedExpression,
    /// Another actual prevents establishing applicability of this signature.
    SignatureApplicability,
}

impl ConversionUnknown {
    pub const LABELS: &'static [&'static str] = &[
        "unsupported_language",
        "unresolved_signature",
        "unresolved_source_type",
        "unresolved_target_type",
        "ambiguous_binding",
        "generic_substitution",
        "unsupported_conversion",
        "unsupported_expression",
        "signature_applicability",
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::UnsupportedLanguage => "unsupported_language",
            Self::UnresolvedSignature => "unresolved_signature",
            Self::UnresolvedSourceType => "unresolved_source_type",
            Self::UnresolvedTargetType => "unresolved_target_type",
            Self::AmbiguousBinding => "ambiguous_binding",
            Self::GenericSubstitution => "generic_substitution",
            Self::UnsupportedConversion => "unsupported_conversion",
            Self::UnsupportedExpression => "unsupported_expression",
            Self::SignatureApplicability => "signature_applicability",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArgumentTypeConversion {
    pub source: ResolvedConversionType,
    pub target: ResolvedConversionType,
    pub kind: ConversionKind,
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
            ConversionKind::JavaBoxing => TransferKind::Boxing,
            ConversionKind::JavaUnboxing => TransferKind::Unboxing,
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
            ConversionKind::JavaIdentity
            | ConversionKind::TypeScriptIdentity
            | ConversionKind::TypeScriptStructuralAssignability
            | ConversionKind::RustIdentity
            | ConversionKind::RustDeref
            | ConversionKind::RustUnsizing
            | ConversionKind::RustReborrow => return None,
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
                ResolvedConversionType::TypeScriptPrimitive(primitive) => {
                    digest.push(b"typescript_primitive");
                    digest.push(&[*primitive as u8]);
                }
                ResolvedConversionType::Rust(identity) => {
                    digest.push(b"rust");
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

struct ConversionSource {
    source: String,
    tree: tree_sitter::Tree,
}

/// One indexed source/tree per file, scoped to the caller's query snapshot.
#[derive(Default)]
pub struct CallConversionCache {
    sources: HashMap<ProjectFile, Option<Arc<ConversionSource>>>,
}

impl CallConversionCache {
    fn source(
        &mut self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
    ) -> Option<Arc<ConversionSource>> {
        self.sources
            .entry(file.clone())
            .or_insert_with(|| {
                let source = analyzer.indexed_source(file)?;
                let tree = parse_tree_for_language(file, language_for_file(file), &source)?;
                Some(Arc::new(ConversionSource { source, tree }))
            })
            .clone()
    }

    /// Resolve conversion typing for a selected source signature and project
    /// only an exact call/target/signature/actual/formal join into binding rows.
    pub fn populate(
        &mut self,
        analyzer: &dyn IAnalyzer,
        report: &mut CallBindingReport,
        signature: Option<&str>,
    ) {
        let language = language_for_file(&report.file);
        let prerequisite = match language_support(language)
            .and_then(LanguageSupport::call_argument_conversion_prover)
        {
            Some(prover) => self.prove(analyzer, report, signature, language, prover),
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
        project_conversion_facts(report, signature, None);
    }

    fn prove(
        &mut self,
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
            if row.argument_id.is_none()
                || matches!(
                    row.binding_kind,
                    Some(CallBindingKind::Receiver | CallBindingKind::Implicit)
                )
            {
                continue;
            }
            let proof = (|| {
                if row.mapping != CallBindingMapping::Exact
                    || row.binding_kind != Some(CallBindingKind::Positional)
                {
                    return Err(ConversionUnknown::AmbiguousBinding);
                }
                let (slot, formal) = ordinary
                    .get(
                        row.formal_index
                            .ok_or(ConversionUnknown::AmbiguousBinding)?,
                    )
                    .ok_or(ConversionUnknown::UnresolvedTargetType)?;
                if slot.variadic.is_some() {
                    return Err(ConversionUnknown::UnsupportedConversion);
                }
                let actual = source
                    .tree
                    .root_node()
                    .named_descendant_for_byte_range(row.range.start_byte, row.range.end_byte)
                    .filter(|node| node.byte_range() == (row.range.start_byte..row.range.end_byte))
                    .ok_or(ConversionUnknown::UnsupportedExpression)?;
                if actual.has_error()
                    || actual.is_missing()
                    || formal.has_error()
                    || formal.is_missing()
                {
                    return Err(ConversionUnknown::UnsupportedExpression);
                }
                prover.prove_argument(
                    analyzer,
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
        if missing_formal
            || proofs.iter().any(|(_, proof)| proof.is_err())
            || report
                .rows
                .iter()
                .any(|row| row.terminal || row.mapping != CallBindingMapping::Exact)
        {
            for (_, proof) in &mut proofs {
                if proof.is_ok() {
                    *proof = Err(ConversionUnknown::SignatureApplicability);
                }
            }
        }
        Ok(proofs)
    }

    /// Select the one model overload whose structured formals accept every
    /// written positional actual. No applicable overload and more than one
    /// applicable overload are distinct typed failures.
    pub fn select_model_signature(
        &mut self,
        analyzer: &dyn IAnalyzer,
        shape: &CallShapeReport,
        caller_source: Option<(&ProjectFile, &str)>,
        candidates: &[(String, Signature)],
    ) -> Result<Option<(String, Signature)>, ConversionUnknown> {
        let language = language_for_file(&shape.outcome.file);
        let Some(prover) =
            language_support(language).and_then(LanguageSupport::call_argument_conversion_prover)
        else {
            return Err(ConversionUnknown::UnsupportedLanguage);
        };
        let source = match self.source(analyzer, &shape.outcome.file) {
            Some(source) => source,
            None => {
                let (file, source) = caller_source
                    .filter(|(file, _)| *file == &shape.outcome.file)
                    .ok_or(ConversionUnknown::UnresolvedSourceType)?;
                let tree = parse_tree_for_language(file, language_for_file(file), source)
                    .ok_or(ConversionUnknown::UnresolvedSourceType)?;
                Arc::new(ConversionSource {
                    source: source.to_owned(),
                    tree,
                })
            }
        };
        let mut written = Vec::new();
        for (formal_index, argument) in shape.arguments.iter().enumerate() {
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
            written.push((formal_index, actual));
        }

        let mut applicable = Vec::new();
        let mut failures = Vec::new();
        for (model_id, signature) in candidates {
            let mut candidate_ok = true;
            for (formal_index, actual) in &written {
                let Some(formal) = signature.parameters.get(*formal_index) else {
                    failures.push(ConversionUnknown::UnresolvedTargetType);
                    candidate_ok = false;
                    break;
                };
                if !formal.passing_mode.accepts_positional() || formal.variadic {
                    failures.push(ConversionUnknown::UnsupportedConversion);
                    candidate_ok = false;
                    break;
                }
                if let Err(reason) = prover.prove_model_argument(
                    analyzer,
                    &shape.outcome.file,
                    *actual,
                    &source.source,
                    &formal.r#type,
                ) {
                    failures.push(reason);
                    candidate_ok = false;
                    break;
                }
            }
            if candidate_ok {
                applicable.push((model_id.clone(), signature.clone()));
            }
        }
        match applicable.as_slice() {
            [(model_id, signature)] => Ok(Some((model_id.clone(), signature.clone()))),
            [] if failures.windows(2).all(|pair| pair[0] == pair[1]) && !failures.is_empty() => {
                Err(failures[0])
            }
            [] => Err(ConversionUnknown::SignatureApplicability),
            _ => Err(ConversionUnknown::AmbiguousBinding),
        }
    }

    /// Populate conversions for the exact model target/signature/actual/formal
    /// join selected by the model call binder.
    pub fn populate_model_signature(
        &mut self,
        analyzer: &dyn IAnalyzer,
        report: &mut CallBindingReport,
        model_target_id: &str,
        signature_id: &str,
        signature: &Signature,
    ) {
        let language = language_for_file(&report.file);
        let prerequisite = language_support(language)
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
        project_conversion_facts(report, Some(signature_id), Some(model_target_id));
    }

    fn prove_model(
        &mut self,
        analyzer: &dyn IAnalyzer,
        report: &CallBindingReport,
        prover: &dyn CallArgumentConversionProver,
        signature: &Signature,
    ) -> Result<Vec<IndexedConversionProof>, ConversionUnknown> {
        let source = self
            .source(analyzer, &report.file)
            .ok_or(ConversionUnknown::UnresolvedSourceType)?;
        let mut proofs = Vec::new();
        for (index, row) in report.rows.iter().enumerate() {
            if row.argument_id.is_none()
                || matches!(
                    row.binding_kind,
                    Some(CallBindingKind::Receiver | CallBindingKind::Implicit)
                )
            {
                continue;
            }
            let proof = (|| {
                if row.mapping != CallBindingMapping::Exact
                    || row.binding_kind != Some(CallBindingKind::Positional)
                {
                    return Err(ConversionUnknown::AmbiguousBinding);
                }
                let formal_index = row
                    .formal_index
                    .ok_or(ConversionUnknown::AmbiguousBinding)?;
                let formal = signature
                    .parameters
                    .get(formal_index)
                    .ok_or(ConversionUnknown::UnresolvedTargetType)?;
                if formal.variadic {
                    return Err(ConversionUnknown::UnsupportedConversion);
                }
                let actual = source
                    .tree
                    .root_node()
                    .named_descendant_for_byte_range(row.range.start_byte, row.range.end_byte)
                    .filter(|node| node.byte_range() == (row.range.start_byte..row.range.end_byte))
                    .ok_or(ConversionUnknown::UnsupportedExpression)?;
                if actual.has_error() || actual.is_missing() {
                    return Err(ConversionUnknown::UnsupportedExpression);
                }
                prover.prove_model_argument(
                    analyzer,
                    &report.file,
                    actual,
                    &source.source,
                    &formal.r#type,
                )
            })();
            proofs.push((index, proof));
        }
        if proofs.iter().any(|(_, proof)| proof.is_err())
            || report
                .rows
                .iter()
                .any(|row| row.terminal || row.mapping != CallBindingMapping::Exact)
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

    #[test]
    fn conversion_labels_and_unknown_reasons_are_stable() {
        assert_eq!(
            ConversionKind::LABELS,
            &[
                "java_identity",
                "java_primitive_widening",
                "java_boxing",
                "java_unboxing",
                "typescript_identity",
                "typescript_structural_assignability",
                "rust_identity",
                "rust_deref",
                "rust_unsizing",
                "rust_reborrow",
            ]
        );
        assert_eq!(
            ConversionUnknown::LABELS,
            &[
                "unsupported_language",
                "unresolved_signature",
                "unresolved_source_type",
                "unresolved_target_type",
                "ambiguous_binding",
                "generic_substitution",
                "unsupported_conversion",
                "unsupported_expression",
                "signature_applicability",
            ]
        );
        for reason in ConversionUnknown::LABELS {
            assert!(reason.as_bytes().iter().all(|byte| byte.is_ascii()));
        }
    }
}
