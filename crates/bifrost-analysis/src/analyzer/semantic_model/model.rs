use schemars::JsonSchema;
use semver::Version;
use serde::{Deserialize, Serialize};

pub const SEMANTIC_MODEL_SCHEMA_VERSION: u32 = 2;
pub const PROCEDURE_SUMMARY_CONTRACT_VERSION: u32 = 1;
pub const MAX_PROCEDURE_SUMMARY_ORDINAL: u32 = 65_535;
pub const MAX_PROCEDURE_SUMMARY_LOCATIONS: usize = 65_536;
pub const MAX_PROCEDURE_SUMMARY_TRANSFERS: usize = 65_536;
pub const MAX_PROCEDURE_SUMMARY_EFFECTS: usize = 65_536;
pub const MAX_PROCEDURE_SUMMARY_AMBIGUOUS_CALLEES: usize = 4_096;
pub const MAX_PROCEDURE_SUMMARY_EFFECT_REFERENCES: usize = 65_536;
pub const MAX_PROCEDURE_SUMMARY_MODEL_ID_BYTES: usize = 512;
/// Upper bound on the labels one `sanitize` effect removes. It mirrors the
/// policy-local `(sanitize :removes [LABEL...])` bound (#1923).
pub const MAX_PROCEDURE_SUMMARY_SANITIZE_LABELS: usize = 64;
/// Upper bound on the namespaced effect identifiers one summary declares
/// (#2437). Declared effects are a small, reviewed vocabulary per procedure,
/// not a log, so the bound stays at the same order as the sanitize-label bound.
pub const MAX_PROCEDURE_SUMMARY_DECLARED_EFFECTS: usize = 64;
/// Upper bound on reviewed relationships among a procedure's normal results.
/// These are API contracts, not observed executions, so one summary should
/// need only a small set.
pub const MAX_PROCEDURE_SUMMARY_RESULT_CONTRACTS: usize = 64;
pub const MAX_RESULT_CONTRACT_MEMBER_CONTRACTS: usize = 64;
pub const MAX_PROCEDURE_SUMMARY_NORMAL_RETURN_REFINEMENTS: usize = 64;
/// Upper bound on reviewed boolean-result outcomes that refine a procedure's
/// parameters. These rows are API contracts rather than observed executions,
/// so one summary should need only a small set.
pub const MAX_PROCEDURE_SUMMARY_CONDITIONAL_RESULT_REFINEMENTS: usize = 64;
pub const MAX_PROCEDURE_SUMMARY_CONDITIONAL_INDIRECT_WRITES: usize = 64;

pub const CPP_RESOLUTION_VOCABULARY: &str = "csmi.c-cpp-resolution";
pub const CPP_RESOLUTION_VERSION: &str = "0.1.0";
pub const CPP_DECLARATION_SCHEME: &str = "csmi.cpp.declaration";
pub const CPP_DECLARATION_SCHEME_VERSION: &str = "0.1.0";
pub const CPP_SIGNATURE_DISAMBIGUATOR_PREFIX: &str = "cppsig-0.1:";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuthoredSemanticModelPack {
    #[schemars(range(min = 2, max = 2))]
    pub schema_version: u32,
    pub pack_id: String,
    pub version: String,
    pub producer: Producer,
    pub language: String,
    pub ecosystem: String,
    pub compatibility: Compatibility,
    pub provenance: Provenance,
    pub license: String,
    pub completeness: Completeness,
    pub safety: Safety,
    /// The producer's explicit claim that it read and parsed each of these
    /// relative source paths from a sources artifact while generating the pack
    /// (#2613). A consumer uses the inventory to distinguish a `Locator::Source`
    /// path the pack carries -- a legitimate authored navigation target -- from
    /// an upstream path the pack merely names, which must render as a durable
    /// `bifrost-model://` location instead.
    ///
    /// Entries are canonical relative slash-separated paths in strictly
    /// ascending order. Serialized only when non-empty, so adding the field
    /// leaves the manifest bytes and digests of every pack that does not carry
    /// sources unchanged -- the same discipline `declared_effects` uses.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub carried_sources: Vec<String>,
    /// Exact resolver-backed C and C++ applicability and declaration evidence.
    ///
    /// This is intentionally a pack-level, optional container.  A pack that
    /// does not carry native C++ evidence omits the field and therefore keeps
    /// its historical serialized form.  Native declaration ids are the
    /// references used by this container; display names and rendered
    /// signatures are never identities.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpp_portability: Option<CppPortabilityEvidence>,
    pub shards: Vec<AuthoredShard>,
}

/// Exact C/C++ portability evidence imported from the CSMI 0.1 C/C++ profile.
///
/// The vectors are sorted into a canonical order by the semantic-pack
/// compiler.  Their contents remain typed all the way through artifact
/// encoding and decoding so a consumer can distinguish an exact resolver
/// result from a missing or unsupported one without inspecting JSON values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CppPortabilityEvidence {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resolution_contexts: Vec<CppResolutionContextRecord>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub symbols: Vec<CppPortableSymbolRecord>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub type_aliases: Vec<CppTypeAliasEvidence>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub special_members: Vec<CppSpecialMemberEvidence>,
}

/// A complete resolver context and the exact digest used to refer to it from
/// alias and special-member facts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CppResolutionContextRecord {
    pub context_digest: String,
    pub language: CppLanguage,
    pub translation_unit: String,
    pub compile_arguments_digest: String,
    pub direct_headers: Vec<CppDirectHeader>,
    pub header_closure: CppHeaderClosure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CppLanguage {
    C,
    Cpp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CppHeaderClosure {
    Complete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CppDirectHeader {
    pub include_name: String,
    pub artifact: CppArtifactSelector,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CppArtifactSelector {
    pub purl: String,
    pub digests: Vec<CppArtifactDigest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CppArtifactDigest {
    pub algorithm: CppDigestAlgorithm,
    pub coverage: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canonicalization: Option<String>,
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum CppDigestAlgorithm {
    Sha256,
}

/// A portable C++ symbol key retained alongside the native declaration id
/// that the Bifrost pack uses for references.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CppPortableSymbolRecord {
    pub native_id: String,
    pub key: CppPortableSymbolKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CppPortableSymbolKey {
    pub artifact_selectors: Vec<CppArtifactSelector>,
    pub scheme: String,
    pub scheme_version: String,
    pub stability: CppIdentityStability,
    pub descriptors: Vec<CppSymbolDescriptor>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CppIdentityStability {
    Portable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CppSymbolDescriptor {
    pub role: CppDescriptorRole,
    pub name: String,
    pub disambiguator: String,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum CppDescriptorRole {
    Namespace,
    Type,
    Callable,
}

/// A type alias fact keyed by the native alias declaration id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CppTypeAliasEvidence {
    pub alias: String,
    pub target: CppCanonicalType,
    pub resolution_context: CppResolutionContextRef,
}

/// The CSMI resolution-profile reference carried by a C++ profile fact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CppResolutionContextRef {
    pub vocabulary: String,
    pub version: String,
    pub context_digest: String,
    pub language: CppLanguage,
    pub header_closure: CppHeaderClosure,
}

/// Closed canonical type tree for C++ identity.  Declared and template
/// primary references use native declaration ids whose complete portable keys
/// are retained in `CppPortabilityEvidence::symbols`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CppCanonicalType {
    Fundamental {
        name: CppFundamentalTypeName,
    },
    Declared {
        symbol: String,
    },
    TemplateSpecialization {
        primary: String,
        arguments: Vec<CppCanonicalType>,
    },
    Qualified {
        qualifiers: Vec<CppTypeQualifier>,
        r#type: Box<CppCanonicalType>,
    },
    Reference {
        reference_kind: CppReferenceKind,
        referent: Box<CppCanonicalType>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CppFundamentalTypeName {
    Char,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum CppTypeQualifier {
    Const,
    Volatile,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CppReferenceKind {
    Lvalue,
    Rvalue,
}

/// An exact copy/move special-member declaration identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CppSpecialMemberEvidence {
    pub owner: String,
    pub member: String,
    pub operation: CppSpecialMemberOperation,
    pub signature: CppCallableSignature,
    pub member_disambiguator: String,
    pub resolution_context: CppResolutionContextRef,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum CppSpecialMemberOperation {
    CopyConstructor,
    CopyAssignment,
    MoveConstructor,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CppCallableSignature {
    pub callable_kind: CppCallableKind,
    pub owner: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receiver: Option<CppCanonicalType>,
    pub parameters: Vec<CppCanonicalType>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<CppCanonicalType>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CppCallableKind {
    Constructor,
    Method,
}

impl CppPortabilityEvidence {
    pub(crate) fn normalize(&mut self) {
        self.resolution_contexts
            .sort_by(|left, right| left.context_digest.cmp(&right.context_digest));
        self.symbols
            .sort_by(|left, right| left.native_id.cmp(&right.native_id));
        self.type_aliases
            .sort_by(|left, right| left.alias.cmp(&right.alias));
        self.special_members.sort_by(|left, right| {
            (&left.owner, &left.member, &left.operation).cmp(&(
                &right.owner,
                &right.member,
                &right.operation,
            ))
        });
        for context in &mut self.resolution_contexts {
            context.direct_headers.sort_by_key(canonical_json_key);
            for header in &mut context.direct_headers {
                normalize_artifact_selector(&mut header.artifact);
            }
        }
        for symbol in &mut self.symbols {
            for selector in &mut symbol.key.artifact_selectors {
                normalize_artifact_selector(selector);
            }
            symbol
                .key
                .artifact_selectors
                .sort_by_key(canonical_json_key);
            for pair in symbol.key.descriptors.windows(2) {
                debug_assert!(
                    pair[0].role <= pair[1].role,
                    "descriptor roles are ordered by resolver ownership"
                );
            }
        }
        for alias in &mut self.type_aliases {
            normalize_cpp_type(&mut alias.target);
        }
        for member in &mut self.special_members {
            if let Some(receiver) = &mut member.signature.receiver {
                normalize_cpp_type(receiver);
            }
            for parameter in &mut member.signature.parameters {
                normalize_cpp_type(parameter);
            }
            if let Some(result) = &mut member.signature.result {
                normalize_cpp_type(result);
            }
        }
    }
}

fn canonical_json_key<T: Serialize>(value: &T) -> Vec<u8> {
    serde_json::to_vec(value).expect("C++ portability evidence is JSON serializable")
}

fn normalize_artifact_selector(selector: &mut CppArtifactSelector) {
    selector.digests.sort_by_key(canonical_json_key);
}

fn normalize_cpp_type(ty: &mut CppCanonicalType) {
    match ty {
        CppCanonicalType::Fundamental { .. } | CppCanonicalType::Declared { .. } => {}
        CppCanonicalType::TemplateSpecialization { arguments, .. } => {
            for argument in arguments {
                normalize_cpp_type(argument);
            }
        }
        CppCanonicalType::Qualified { qualifiers, r#type } => {
            qualifiers.sort_unstable();
            normalize_cpp_type(r#type);
        }
        CppCanonicalType::Reference { referent, .. } => normalize_cpp_type(referent),
    }
}

/// The distinct `Locator::Source` paths across a pack's declaration facts, in
/// strictly ascending order.
///
/// Only a producer whose `Locator::Source` paths are, by construction, entries
/// it actually parsed from a sources artifact may use this to populate
/// `AuthoredSemanticModelPack::carried_sources`; the call site is the claim.
pub fn carried_source_paths(shards: &[AuthoredShard]) -> Vec<String> {
    let mut paths: Vec<String> = shards
        .iter()
        .flat_map(|shard| match &shard.payload {
            AuthoredPayload::DeclarationFacts { types, members, .. } => types
                .iter()
                .map(|fact| &fact.locator)
                .chain(members.iter().map(|fact| &fact.locator))
                .filter_map(|locator| match locator {
                    Locator::Source { path, .. } => Some(path.clone()),
                    Locator::Artifact { .. } => None,
                })
                .collect::<Vec<_>>(),
            AuthoredPayload::GeneratorRules { .. } | AuthoredPayload::ProcedureSummaries { .. } => {
                Vec::new()
            }
        })
        .collect();
    paths.sort_unstable();
    paths.dedup();
    paths
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Producer {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Compatibility {
    pub bifrost: String,
    #[serde(default)]
    pub toolchains: Vec<VersionConstraint>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VersionConstraint {
    pub name: String,
    pub requirement: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Completeness {
    Partial,
    Complete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Safety {
    #[serde(default)]
    pub generated_code_only: bool,
    #[serde(default)]
    pub review_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuthoredShard {
    pub id: String,
    pub activation: Vec<ActivationSelector>,
    pub payload: AuthoredPayload,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthoredPayload {
    DeclarationFacts {
        #[serde(default)]
        types: Vec<TypeFact>,
        #[serde(default)]
        members: Vec<MemberFact>,
        #[serde(default)]
        relations: Vec<RelationFact>,
    },
    GeneratorRules {
        rules: Vec<GeneratorRule>,
    },
    ProcedureSummaries {
        summaries: Vec<AuthoredProcedureSummary>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuthoredProcedureSummary {
    pub id: String,
    pub target: AuthoredProcedureTarget,
    pub completeness: Completeness,
    /// The author's explicit claim that every implementation of this member
    /// outside the workspace conforms to this summary (#2371).
    ///
    /// This is a statement about the member's *implementations*, not about this
    /// summary's own coverage of its target, so it is deliberately not inherited
    /// from `completeness: complete`. Only a summary carrying it can discharge a
    /// call's residual dynamic-dispatch arm, and only after the workspace
    /// implementors of the same declaring member have been enumerated.
    ///
    /// Serialized only when claimed, so adding the field leaves the content
    /// digest of every summary that does not claim it unchanged.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub covers_overrides: bool,
    /// The author's explicit claim that this procedure has no normal
    /// continuation. Omission or `false` makes no claim; only `true` may remove
    /// normal control after exact runtime agreement.
    ///
    /// Serialized only when claimed, so adding the field leaves the content
    /// digest of every existing summary unchanged.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub normal_continuation_absent: bool,
    /// Number of normal result ports the target returns. It is required when
    /// `result_contracts` or `conditional_result_refinements` is non-empty so
    /// the compiler can reject invalid ordinals without materializing a source
    /// declaration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub normal_result_count: Option<u32>,
    #[serde(default)]
    pub locations: Vec<AuthoredSummaryLocation>,
    pub transfers: Vec<AuthoredSummaryTransfer>,
    #[serde(default)]
    pub effects: Vec<AuthoredSummaryEffect>,
    /// Reviewed concurrency semantics for this exact callable. These effects
    /// name receiver or parameter ports and are projected at an applicable
    /// call site; they do not add value-flow edges to `effects`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub concurrency_effects: Vec<AuthoredConcurrencyEffect>,
    /// Namespaced effect identifiers the reviewed pack attributes to this exact
    /// procedure identity (#2437), for example `acme.network_io`.
    ///
    /// These are declarations *about* the procedure, not dataflow ports: unlike
    /// `effects`, they carry no input, output, or callee and are never lowered
    /// into the summary's transfer graph. They exist so a policy can ask "does
    /// this call perform this effect?" without new analyzer code.
    ///
    /// Serialized only when non-empty, so adding the field leaves the content
    /// digest of every summary that does not declare an effect unchanged --
    /// the same discipline `covers_overrides` uses above.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub declared_effects: Vec<AuthoredDeclaredEffect>,
    /// Reviewed predicates required of this exact procedure invocation's
    /// inputs. Omission means operation preconditions were not reviewed; a
    /// present empty list means the procedure was reviewed and requires none.
    ///
    /// Serialized only when reviewed so adding this field leaves every
    /// existing authored summary's canonical bytes and content digest
    /// unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preconditions: Option<Vec<AuthoredOperationPrecondition>>,
    /// Reviewed conditions under which one normal result is valid to consume.
    /// A contract may name a separate condition result, as in a Go
    /// `(resource, error)` API, or state a validity predicate directly on the
    /// protected result. The relation is explicit because return shape alone
    /// does not establish either contract.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub result_contracts: Vec<AuthoredResultContract>,
    /// Reviewed effects that one boolean normal-result outcome has on a
    /// predicate over a parameter. A negative proof effect says only that the
    /// outcome does not prove the named predicate; it does not establish the
    /// opposite runtime value.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditional_result_refinements: Vec<AuthoredConditionalResultRefinement>,
    /// Outcome-sensitive writes through one pointer-like parameter. The
    /// target is deliberately one-step: deeper access paths require explicit
    /// location machinery rather than an encoded path string.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditional_indirect_writes: Vec<AuthoredConditionalIndirectWrite>,
    /// Reviewed predicates established for parameters whenever this procedure
    /// returns normally. These are path postconditions, not unconditional
    /// claims about the argument at call entry.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub normal_return_refinements: Vec<AuthoredNormalReturnRefinement>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuthoredConditionalResultRefinement {
    #[schemars(range(max = 65535))]
    pub result_ordinal: u32,
    pub outcome: bool,
    #[schemars(range(max = 65535))]
    pub parameter_ordinal: u32,
    pub predicate: AuthoredResultPredicate,
    pub proof_effect: AuthoredPredicateProofEffect,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuthoredConditionalIndirectWrite {
    #[schemars(range(max = 65535))]
    pub result_ordinal: u32,
    pub outcome: bool,
    #[schemars(range(max = 65535))]
    pub parameter_ordinal: u32,
    pub target: AuthoredIndirectWriteTarget,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AuthoredIndirectWriteTarget {
    Pointee,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AuthoredPredicateProofEffect {
    Establishes,
    DoesNotEstablish,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuthoredNormalReturnRefinement {
    #[schemars(range(max = 65535))]
    pub parameter_ordinal: u32,
    pub predicate: AuthoredResultPredicate,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuthoredResultContract {
    #[schemars(range(max = 65535))]
    pub result_ordinal: u32,
    /// A separate result whose reviewed predicate establishes that the
    /// protected result is valid. Omit this together with `predicate` when
    /// validity is expressed directly by `result_success_predicate`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(range(max = 65535))]
    pub condition_result_ordinal: Option<u32>,
    /// The predicate required of `condition_result_ordinal`. This field and
    /// the condition ordinal must be present or absent together.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predicate: Option<AuthoredResultPredicate>,
    /// The reviewed predicate that makes the protected result valid. For a
    /// paired contract, this is an optional correlation that independently
    /// proves the separate condition predicate. For a direct contract, this
    /// is the validity predicate and is required.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_success_predicate: Option<AuthoredResultPredicate>,
    /// Reviewed member behavior carried by this exact result port. This lets a
    /// pack describe a resource returned by a multi-result API without
    /// attributing the same protocol to the other result ports.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub member_contracts: Vec<AuthoredResultMemberContract>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuthoredResultMemberContract {
    pub member: String,
    #[schemars(range(max = 65535))]
    pub parameter_count: u32,
    pub completeness: Completeness,
    /// Reviewed predicates required of this exact member operation's inputs.
    /// Omission means operation preconditions were not reviewed; a present
    /// empty list means the operation was reviewed and requires none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preconditions: Option<Vec<AuthoredOperationPrecondition>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub declared_effects: Vec<AuthoredDeclaredEffect>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuthoredOperationPrecondition {
    pub input: AuthoredSummaryInput,
    pub predicate: AuthoredResultPredicate,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AuthoredResultPredicate {
    Null,
    NonNull,
    True,
    False,
}

/// One namespaced effect a reviewed pack attributes to a procedure (#2437).
///
/// `id` is a namespaced identifier (`vendor.effect`); the namespace separator is
/// required so two vendors can ship packs without colliding on bare words like
/// `write`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuthoredDeclaredEffect {
    pub id: String,
    pub timing: DeclaredEffectTiming,
    pub certainty: DeclaredEffectCertainty,
}

/// When the declared effect happens relative to the call that triggers it.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum DeclaredEffectTiming {
    /// The effect happens before the call returns.
    Immediate,
    /// The call schedules the effect; it happens after the call returns.
    Deferred,
    /// The pack asserts the effect without claiming when it happens.
    Unknown,
}

/// How firmly the reviewed pack claims the effect occurs.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum DeclaredEffectCertainty {
    /// Every execution of the procedure performs the effect.
    Definite,
    /// Some execution of the procedure may perform the effect.
    Possible,
}

// `authored_procedure_target_identity` is the one reader of the rule below.
// Every index and match site goes through it instead of splitting `symbol`
// itself, so the authored side and `modeled_procedure_key` agree by
// construction (#2610).
/// The exact declaration one reviewed summary speaks for.
///
/// `symbol` has two authored forms, and they differ in what supplies the
/// procedure's owner. A qualified symbol names its own owner, so `Acme.run` at
/// `path: "src/acme.ts"` keys on owner `Acme` and member `run`; the path is
/// provenance and the artifact locator, and does not enter the identity. A
/// bare symbol is a module-level declaration, which has no owner in its name at
/// all: the module the `path` names is its owner, so `run` at
/// `path: "src/run.ts"` keys on owner `src/run` and member `run`, the path with
/// its extension removed. The bare form is the only one available for a
/// top-level function in a language that qualifies nothing by package, such as
/// JavaScript, TypeScript, or Ruby.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuthoredProcedureTarget {
    pub path: String,
    pub symbol: String,
    #[serde(default)]
    pub has_receiver: bool,
    /// Whether the final formal parameter accepts zero or more actual
    /// arguments. `parameter_count` includes that final variadic formal, so a
    /// variadic target accepts at least `parameter_count - 1` actual arguments.
    /// Semantic claims may currently reference only the fixed prefix: the
    /// validator rejects a port or refinement that names the variadic tail.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    #[schemars(extend("default" = false))]
    pub variadic: bool,
    pub parameter_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuthoredSummaryLocation {
    pub id: String,
    pub location_kind: AuthoredSummaryLocationKind,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AuthoredSummaryLocationKind {
    Capture,
    Heap,
}

#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthoredSummaryInput {
    Receiver {},
    Parameter {
        #[schemars(range(max = 65535))]
        ordinal: u32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthoredSummaryOutput {
    NormalReturn {},
    IndexedNormalReturn {
        #[schemars(range(max = 65535))]
        ordinal: u32,
    },
    Receiver {},
    Capture {
        location: String,
    },
    Heap {
        location: String,
    },
    ExceptionalReturn {},
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuthoredSummaryTransfer {
    pub input: AuthoredSummaryInput,
    pub exit_kind: AuthoredSummaryExitKind,
    pub output: AuthoredSummaryOutput,
    /// Optional identity-separating value-transfer semantics for this core
    /// transfer. The endpoints remain the core transfer's ports; this field
    /// only classifies the value/identity relationship and selected
    /// operation. Omission means this profile was not reviewed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_transfer: Option<SummaryValueTransfer>,
}

/// Typed identity-separating semantics attached to one procedure-summary
/// transfer. This is intentionally separate from the core transfer endpoints
/// so a consumer can distinguish value-flow coverage from profile coverage.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SummaryValueTransfer {
    pub kind: SummaryValueTransferKind,
    pub operation: SummaryValueTransferOperation,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SummaryValueTransferKind {
    Copy {},
    AggregateCopy {},
    Move {
        invalidation: SummaryMoveInvalidation,
    },
    Conversion {
        preservation: SummaryValuePreservation,
    },
    Boxing {},
    Unboxing {},
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum SummaryMoveInvalidation {
    Invalidated,
    Unknown,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum SummaryValuePreservation {
    Identity,
    Preserving,
    Changing,
    Unknown,
}

/// The selected operation behind one value transfer. An implicit operation
/// names the exact stable member declaration id; it never carries a display
/// name or rendered signature. Unknown operation identity remains typed and
/// carries the reason it could not be established.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SummaryValueTransferOperation {
    None {},
    Implicit {
        member: String,
    },
    Unknown {
        limitation: SummaryValueTransferLimitation,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SummaryValueTransferLimitation {
    pub kind: SummaryValueTransferLimitationKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum SummaryValueTransferLimitationKind {
    BudgetExhausted,
    Cancelled,
    Unsupported,
    UnresolvedIdentity,
    AmbiguousIdentity,
    IncompleteInput,
    Other,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AuthoredSummaryExitKind {
    Normal,
    Exceptional,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthoredSummaryEffect {
    Allocation {
        event: String,
        output: AuthoredSummaryOutput,
    },
    Call {
        event: String,
        callee: String,
    },
    Escape {
        event: String,
        input: AuthoredSummaryInput,
    },
    UnknownCall {
        event: String,
        input: AuthoredSummaryInput,
    },
    UnknownCallBoundary {
        event: String,
    },
    AmbiguousCall {
        event: String,
        input: AuthoredSummaryInput,
        candidates: Vec<String>,
    },
    /// Remove the named labels as a tainted value crosses this input-to-output
    /// transfer. This is the shipped-pack mirror of the policy-local
    /// `(sanitize :removes [LABEL...])` effect (#1923). The `input` and `output`
    /// ports identify a declared transfer; the effect neutralizes the named
    /// labels on that modeled flow and leaves every other label flowing.
    Sanitize {
        input: AuthoredSummaryInput,
        output: AuthoredSummaryOutput,
        removes: Vec<String>,
    },
}

#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthoredConcurrencyEffect {
    Unsupported {
        protocol: String,
    },
    TaskSpawn {
        callable: AuthoredSummaryInput,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        group: Option<AuthoredSummaryInput>,
    },
    TaskJoin {
        group: AuthoredSummaryInput,
    },
    LockAcquire {
        lock: AuthoredSummaryInput,
        mode: AuthoredLockMode,
    },
    LockRelease {
        lock: AuthoredSummaryInput,
        mode: AuthoredLockMode,
    },
    WaitGroupAdd {
        group: AuthoredSummaryInput,
        delta: AuthoredSummaryInput,
    },
    WaitGroupDone {
        group: AuthoredSummaryInput,
    },
    WaitGroupWait {
        group: AuthoredSummaryInput,
    },
    Atomic {
        location: AuthoredSummaryInput,
        operation: AuthoredAtomicOperation,
    },
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AuthoredLockMode {
    Shared,
    Exclusive,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AuthoredAtomicOperation {
    Load,
    Store,
    ReadModifyWrite,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ActivationSelector {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package: Option<NameSelector>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub module: Option<NameSelector>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub toolchain: Option<NameSelector>,
    #[serde(default)]
    pub targets: Vec<String>,
    #[serde(default)]
    pub configurations: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NameSelector {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TypeFact {
    pub id: String,
    pub name: String,
    pub type_kind: TypeKind,
    pub visibility: Visibility,
    #[serde(default)]
    pub is_abstract: bool,
    #[serde(default)]
    pub is_sealed: bool,
    #[serde(default)]
    pub has_explicit_type_terms: bool,
    #[serde(default)]
    pub type_parameters: Vec<String>,
    #[serde(default)]
    pub type_parameter_constraints: Vec<TypeParameterConstraint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub underlying_type: Option<StructuredTypeExpression>,
    /// Type-wide value-transfer semantics. This is deliberately optional:
    /// absence means that the producer did not review implicit value
    /// operations, rather than that the type has no such operations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_semantics: Option<TypeValueSemantics>,
    #[serde(default)]
    pub embedded_types: Vec<EmbeddedTypeFact>,
    #[serde(default)]
    pub hierarchy: Vec<HierarchyFact>,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub extension_surfaces: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guard: Option<DeclarationGuard>,
    pub locator: Locator,
}

/// Reviewed value semantics for a declared type. Copy behavior and move
/// invalidation are independent because a type such as `std::string` can have
/// both a copy constructor and an invalidating move. Member references use
/// stable declaration ids, never names or rendered signatures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TypeValueSemantics {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub copy: Option<TypeCopySemantics>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub move_semantics: Option<TypeMoveSemantics>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TypeCopySemantics {
    Trivial,
    ViaMember { member: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TypeMoveSemantics {
    Invalidating,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TypeKind {
    Class,
    Annotation,
    Delegate,
    Interface,
    Trait,
    Struct,
    Union,
    Enum,
    Record,
    Module,
    TypeAlias,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HierarchyFact {
    pub hierarchy_kind: HierarchyKind,
    pub target: TypeRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declaration_ordinal: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HierarchyKind {
    Extends,
    Implements,
    UsesTrait,
    MixinInclude,
    MixinPrepend,
    MixinExtend,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MemberFact {
    pub id: String,
    pub owner: String,
    pub name: String,
    pub member_kind: MemberKind,
    pub visibility: Visibility,
    #[serde(default)]
    pub is_static: bool,
    #[serde(default)]
    pub is_abstract: bool,
    #[serde(default)]
    pub is_virtual: bool,
    /// Reviewed role of this exact member in implicit value operations.
    /// The member's own stable `id` is the operation identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub implicit_operation: Option<ImplicitOperation>,
    /// The authored declarations contain every callable with this member's
    /// exact owner, name, receiver form, and fixed arity.
    ///
    /// This is narrower than pack or owner-surface completeness. It permits
    /// an exact external-call binding for this one structural family while a
    /// curated declaration pack remains globally partial. Same-family
    /// duplicates still conflict, and variadic families cannot yet make this
    /// claim.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    #[schemars(extend("default" = false))]
    pub callable_family_complete: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<Signature>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receiver: Option<ReceiverFact>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extension_receiver: Option<TypeRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extension_receiver_constraints: Vec<TypeRef>,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guard: Option<DeclarationGuard>,
    pub locator: Locator,
}

/// A declaration-level role for an implicit value operation. Conversion
/// operators retain their structured target type; consumers must still bind
/// the member by its exact declaration id and signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ImplicitOperation {
    CopyConstructor,
    MoveConstructor,
    /// Construction creates a distinct object whose relevant logical value is
    /// preserved from one source argument. Consumers must still prove that the
    /// exact member accepts the source expression at the call site.
    ValuePreservingConstructor,
    CopyAssignment,
    MoveAssignment,
    ConversionOperator {
        target: TypeRef,
    },
}

/// The condition under which one activation declares a record.
///
/// A reference surface can spell a declaration inside a conditional block.
/// Typeshed guards `builtins.float.from_number` with
/// `if sys.version_info >= (3, 14):` and `os.startfile` with
/// `if sys.platform == "win32":`. Publishing the union of every branch with no
/// guard makes a published name mean only "some supported toolchain declares
/// this somewhere", which is a false positive for a presence claim (#1899).
///
/// Every recorded constraint is a *necessary* condition for the record to
/// exist. A producer that cannot interpret part of a condition records
/// [`Self::uninterpreted`] and drops that part rather than the declaration, so
/// the guard never claims more than the producer read. Activation may drop a
/// record only when [`Self::excludes`] proves the pinned activation cannot
/// declare it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeclarationGuard {
    /// Lowest toolchain version that declares this record, inclusive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_toolchain_version: Option<GuardVersion>,
    /// Lowest toolchain version that no longer declares this record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_toolchain_version_exclusive: Option<GuardVersion>,
    /// Activation targets that declare this record. Empty places no
    /// requirement on the target.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_targets: Vec<String>,
    /// Activation targets that do not declare this record.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub excluded_targets: Vec<String>,
    /// The producer read a condition it could not express here. The recorded
    /// constraints stay necessary, but they are not the whole condition, so a
    /// record this flag marks is never dropped for want of a constraint.
    #[serde(default)]
    pub uninterpreted: bool,
}

/// One toolchain-version bound a guard names, padded to three components.
///
/// A source condition can name fewer components than a toolchain version
/// carries, as `sys.version_info >= (3, 14)` does. Padding with zeros keeps
/// one comparable shape, and comparing only the three release components keeps
/// a pre-release toolchain on the same side of a bound as its release.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct GuardVersion {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
}

impl GuardVersion {
    pub fn new(major: u64, minor: u64, patch: u64) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    pub fn of(version: &Version) -> Self {
        Self::new(version.major, version.minor, version.patch)
    }
}

impl DeclarationGuard {
    /// A guard that records only "this producer read a condition it could not
    /// express". It never excludes an activation.
    pub fn uninterpreted() -> Self {
        Self {
            uninterpreted: true,
            ..Self::default()
        }
    }

    /// How many constraints this guard records, ignoring
    /// [`Self::uninterpreted`].
    fn constraint_count(&self) -> usize {
        usize::from(self.min_toolchain_version.is_some())
            + usize::from(self.max_toolchain_version_exclusive.is_some())
            + usize::from(!self.required_targets.is_empty())
            + usize::from(!self.excluded_targets.is_empty())
    }

    /// The guard of a declaration that holds only when both guards hold, as a
    /// declaration nested in two conditional blocks does.
    pub fn and(&self, other: &Self) -> Self {
        let required_targets = if self.required_targets.is_empty() {
            other.required_targets.clone()
        } else if other.required_targets.is_empty() {
            self.required_targets.clone()
        } else {
            self.required_targets
                .iter()
                .filter(|target| other.required_targets.contains(target))
                .cloned()
                .collect::<Vec<_>>()
        };
        // Two disjoint requirements describe a declaration no target
        // declares, which an empty `required_targets` would read as "every
        // target". Record the honest weaker statement instead: something here
        // is not expressible, so nothing here excludes an activation.
        let contradictory = required_targets.is_empty()
            && !self.required_targets.is_empty()
            && !other.required_targets.is_empty();
        let mut excluded_targets = self.excluded_targets.clone();
        excluded_targets.extend(other.excluded_targets.iter().cloned());
        excluded_targets.sort_unstable();
        excluded_targets.dedup();
        Self {
            min_toolchain_version: self.min_toolchain_version.max(other.min_toolchain_version),
            max_toolchain_version_exclusive: match (
                self.max_toolchain_version_exclusive,
                other.max_toolchain_version_exclusive,
            ) {
                (Some(left), Some(right)) => Some(left.min(right)),
                (bound, None) | (None, bound) => bound,
            },
            required_targets,
            excluded_targets,
            uninterpreted: self.uninterpreted || other.uninterpreted || contradictory,
        }
    }

    /// The guard of the branch this guard's condition does not take, when that
    /// branch is expressible.
    ///
    /// Only one recorded constraint negates to one constraint: the complement
    /// of a half-line is a half-line, and the complement of a target set is
    /// its exclusion. A conjunction negates to a disjunction, which this shape
    /// cannot hold, so the caller records [`Self::uninterpreted`] instead.
    pub fn negated(&self) -> Option<Self> {
        if self.uninterpreted || self.constraint_count() != 1 {
            return None;
        }
        if let Some(min) = self.min_toolchain_version {
            return Some(Self {
                max_toolchain_version_exclusive: Some(min),
                ..Self::default()
            });
        }
        if let Some(max) = self.max_toolchain_version_exclusive {
            return Some(Self {
                min_toolchain_version: Some(max),
                ..Self::default()
            });
        }
        if !self.required_targets.is_empty() {
            return Some(Self {
                excluded_targets: self.required_targets.clone(),
                ..Self::default()
            });
        }
        Some(Self {
            required_targets: self.excluded_targets.clone(),
            ..Self::default()
        })
    }

    /// The guard of a declaration that two branches both declare.
    ///
    /// A constraint survives only when both branches state it, so an
    /// unguarded branch makes the declaration unguarded and two different
    /// guards leave nothing necessary behind.
    pub fn union(left: Option<Self>, right: Option<Self>) -> Option<Self> {
        match (left, right) {
            (Some(left), Some(right)) if left == right => Some(left),
            (Some(_), Some(_)) => Some(Self::uninterpreted()),
            _ => None,
        }
    }

    /// Whether this guard proves that an activation pinned to
    /// `toolchain_version` and `target` does not declare the record.
    ///
    /// An unknown coordinate proves nothing, so a missing version or target
    /// never excludes. [`Self::uninterpreted`] does not disable the recorded
    /// constraints: each one stays a necessary condition for the record to
    /// exist, whatever the part the producer could not read says.
    pub fn excludes(&self, toolchain_version: Option<&Version>, target: Option<&str>) -> bool {
        if let Some(version) = toolchain_version {
            let pinned = GuardVersion::of(version);
            if self.min_toolchain_version.is_some_and(|min| pinned < min) {
                return true;
            }
            if self
                .max_toolchain_version_exclusive
                .is_some_and(|max| pinned >= max)
            {
                return true;
            }
        }
        if let Some(target) = target {
            if !self.required_targets.is_empty()
                && !self.required_targets.iter().any(|name| name == target)
            {
                return true;
            }
            if self.excluded_targets.iter().any(|name| name == target) {
                return true;
            }
        }
        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MemberKind {
    Constructor,
    Method,
    Function,
    Field,
    Property,
    Constant,
    Static,
    Macro,
    Event,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Visibility {
    Public,
    Protected,
    Internal,
    ProtectedInternal,
    Package,
    Private,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StructuredTypeExpression {
    pub display: String,
    #[serde(default)]
    pub referenced_types: Vec<TypeRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TypeParameterConstraint {
    pub parameter: String,
    pub constraint: StructuredTypeExpression,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EmbeddedTypeFact {
    pub target: TypeRef,
    #[serde(default)]
    pub pointer: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReceiverFact {
    #[serde(default)]
    pub pointer: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Signature {
    #[serde(default)]
    pub type_parameters: Vec<String>,
    #[serde(default)]
    pub parameters: Vec<Parameter>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub returns: Option<TypeRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Parameter {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub r#type: TypeRef,
    #[serde(default)]
    pub optional: bool,
    #[serde(default)]
    pub variadic: bool,
    #[serde(default, skip_serializing_if = "ParameterPassingMode::is_default")]
    pub passing_mode: ParameterPassingMode,
}

/// Which source-level argument forms may bind one formal parameter.
///
/// Most languages permit both positional and named application. Python stubs
/// additionally use `/` and `*` to declare positional-only and named-only
/// regions; preserving that distinction prevents an exact model binding from
/// accepting a call the declared API itself rejects.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ParameterPassingMode {
    PositionalOnly,
    #[default]
    PositionalOrNamed,
    NamedOnly,
}

impl ParameterPassingMode {
    pub const fn accepts_positional(self) -> bool {
        matches!(self, Self::PositionalOnly | Self::PositionalOrNamed)
    }

    pub const fn accepts_named(self) -> bool {
        matches!(self, Self::PositionalOrNamed | Self::NamedOnly)
    }

    fn is_default(value: &Self) -> bool {
        *value == Self::default()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TypeRef {
    Named {
        name: String,
        #[serde(default)]
        arguments: Vec<TypeRef>,
        #[serde(default)]
        nullable: bool,
    },
    Declared {
        id: String,
        #[serde(default)]
        arguments: Vec<TypeRef>,
        #[serde(default)]
        nullable: bool,
    },
    TypeParameter {
        name: String,
    },
    Array {
        element: Box<TypeRef>,
    },
    ByRef {
        element: Box<TypeRef>,
        /// The reference category, when the source language distinguishes
        /// lvalue and rvalue references. Existing producers omit this field
        /// and therefore retain the historical lvalue-reference meaning.
        #[serde(default, skip_serializing_if = "TypeRefReferenceKind::is_lvalue")]
        reference_kind: TypeRefReferenceKind,
    },
    Pointer {
        element: Box<TypeRef>,
    },
    Slice {
        element: Box<TypeRef>,
    },
    FixedArray {
        element: Box<TypeRef>,
        length: String,
    },
    Map {
        key: Box<TypeRef>,
        value: Box<TypeRef>,
    },
    Channel {
        element: Box<TypeRef>,
        direction: ChannelDirection,
    },
    Wildcard {
        variance: WildcardVariance,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        bound: Option<Box<TypeRef>>,
    },
    Tuple {
        elements: Vec<TypeRef>,
    },
    Function {
        parameters: Vec<Parameter>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        result: Option<Box<TypeRef>>,
    },
}

/// The source-level category of a by-reference type.
///
/// This is separate from the tagged [`TypeRef`] variant because the outer
/// `kind` field already identifies the type constructor. Keeping the category
/// here lets C++ copy and move overloads retain distinct parameter identities,
/// while producers that do not distinguish categories continue to use the
/// default lvalue form.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TypeRefReferenceKind {
    #[default]
    Lvalue,
    Rvalue,
}

impl TypeRefReferenceKind {
    fn is_lvalue(&self) -> bool {
        matches!(self, Self::Lvalue)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ChannelDirection {
    Bidirectional,
    Receive,
    Send,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WildcardVariance {
    Any,
    Extends,
    Super,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Locator {
    Source {
        path: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        symbol: Option<String>,
    },
    Artifact {
        path: String,
        symbol: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RelationFact {
    pub id: String,
    pub relation_kind: RelationKind,
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RelationKind {
    NavigatesTo,
    References,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GeneratorRule {
    pub id: String,
    pub trigger: RuleTrigger,
    #[serde(default)]
    pub captures: Vec<CaptureDeclaration>,
    pub emissions: Vec<RuleEmission>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RuleTrigger {
    LanguageConstruct {
        construct: String,
    },
    Annotation {
        name: String,
    },
    AnnotatedField {
        annotation: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        value: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        excluded_annotations: Vec<String>,
        owner_annotation_path: Vec<String>,
    },
    MacroInvocation {
        name: String,
    },
    GeneratorInvocation {
        name: String,
    },
    ResolvedOwner {
        owner: String,
    },
    ResolvedCall {
        owner: String,
        name: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CaptureDeclaration {
    pub name: String,
    pub binding: CaptureBinding,
    pub value_kind: CaptureValueKind,
    pub cardinality: CaptureCardinality,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CaptureBinding {
    pub source: CaptureSource,
    pub projection: CaptureProjection,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CaptureSource {
    MatchedNode,
    EnclosingDeclaration,
    OwningType,
    /// Direct authored fields that supply generated members. A field-level
    /// annotation produces that field; a type-level annotation produces its
    /// direct fields.
    OwnedFields,
    OwnedMutableFields,
    /// Direct non-static final fields without an authored initializer. The
    /// matcher preserves declaration order for generated constructor inputs.
    OwnedUninitializedFinalFields,
    ResolvedOwner,
    Argument {
        index: u32,
    },
    Arguments {
        from: u32,
    },
    AnnotationArgument {
        name: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CaptureProjection {
    Name,
    StableId,
    Type,
    Text,
    Path,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CaptureValueKind {
    Identifier,
    StableId,
    Type,
    String,
    Path,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CaptureCardinality {
    One,
    Optional,
    Many,
    /// Keep ordered values together for one emission instead of emitting one
    /// rule match for each value.
    Group,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RuleEmission {
    Declaration {
        id: TemplateExpression,
        name: TemplateExpression,
        /// A capture-backed authored location for the emitted declaration.
        /// The runtime uses a stable model URI when this expression has no
        /// exact authored anchor.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        anchor: Option<TemplateExpression>,
        declaration: EmittedDeclaration,
    },
    Alias {
        id: TemplateExpression,
        from: TemplateExpression,
        to: TemplateExpression,
    },
    Relation {
        id: TemplateExpression,
        relation_kind: RelationKind,
        from: TemplateExpression,
        to: TemplateExpression,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EmittedDeclaration {
    Type {
        type_kind: TypeKind,
        visibility: Visibility,
        #[serde(default)]
        is_abstract: bool,
        #[serde(default)]
        is_sealed: bool,
        #[serde(default)]
        type_parameters: Vec<TemplateExpression>,
        #[serde(default)]
        hierarchy: Vec<TemplateHierarchyFact>,
        #[serde(default)]
        extension_surfaces: Vec<TemplateExpression>,
    },
    Member {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        owner: Option<TemplateExpression>,
        member_kind: MemberKind,
        visibility: Visibility,
        #[serde(default)]
        is_static: bool,
        #[serde(default)]
        is_abstract: bool,
        #[serde(default)]
        is_virtual: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        signature: Option<TemplateSignature>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TemplateHierarchyFact {
    pub hierarchy_kind: HierarchyKind,
    pub target: TemplateTypeRef,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TemplateSignature {
    #[serde(default)]
    pub type_parameters: Vec<TemplateExpression>,
    #[serde(default)]
    pub parameters: Vec<TemplateParameter>,
    #[serde(default)]
    pub repeated_parameters: Vec<TemplateParameter>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub returns: Option<TemplateTypeRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TemplateParameter {
    pub name: TemplateExpression,
    pub r#type: TemplateTypeRef,
    #[serde(default)]
    pub optional: bool,
    #[serde(default)]
    pub variadic: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TemplateTypeRef {
    Named {
        name: TemplateExpression,
        #[serde(default)]
        arguments: Vec<TemplateTypeRef>,
        #[serde(default)]
        nullable: bool,
    },
    Capture {
        name: String,
    },
    Array {
        element: Box<TemplateTypeRef>,
    },
    ByRef {
        element: Box<TemplateTypeRef>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum TemplateExpression {
    Literal {
        value: String,
    },
    Capture {
        name: String,
    },
    Concat {
        values: Vec<TemplateExpression>,
    },
    Transform {
        transform: AsciiTransform,
        value: Box<TemplateExpression>,
    },
    Conditional {
        condition: TemplateCondition,
        #[serde(rename = "then")]
        then_value: Box<TemplateExpression>,
        #[serde(rename = "else")]
        else_value: Box<TemplateExpression>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum TemplateCondition {
    Equals {
        left: Box<TemplateExpression>,
        right: Box<TemplateExpression>,
    },
    StartsWith {
        value: Box<TemplateExpression>,
        prefix: Box<TemplateExpression>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AsciiTransform {
    Lowercase,
    Uppercase,
    SnakeCase,
    KebabCase,
    PascalCase,
    CamelCase,
}

impl AuthoredPayload {
    pub(crate) fn record_count(&self) -> usize {
        match self {
            Self::DeclarationFacts {
                types,
                members,
                relations,
            } => types.len() + members.len() + relations.len(),
            Self::GeneratorRules { rules } => rules.len(),
            Self::ProcedureSummaries { summaries } => summaries.len(),
        }
    }
}

pub(crate) fn normalize_artifact_locator_paths(pack: &mut AuthoredSemanticModelPack, path: &str) {
    for shard in &mut pack.shards {
        let AuthoredPayload::DeclarationFacts { types, members, .. } = &mut shard.payload else {
            continue;
        };
        for locator in types
            .iter_mut()
            .map(|fact| &mut fact.locator)
            .chain(members.iter_mut().map(|fact| &mut fact.locator))
        {
            if let Locator::Artifact {
                path: locator_path, ..
            } = locator
            {
                *locator_path = path.to_owned();
            }
        }
    }
}
