//! Bounded lookup of declarations by name.
//!
//! [`CodeUnitIndex`] answers from one analyzer's own declarations.  A resolver
//! or a language scan usually needs a wider view than that -- "does the
//! workspace define this fq name at all" -- and the implementations that can
//! answer it differ in how much they are allowed to touch: a whole-workspace
//! index answers from memory, while a persisted analyzer must route the same
//! question through bounded store queries instead of materializing every
//! declaration.  [`BoundedDefinitionLookup`] is the contract both satisfy, so a
//! caller taking `&dyn BoundedDefinitionLookup` cannot accidentally opt into
//! the unbounded one.
//!
//! The trait lives here, below the usages framework that owns its
//! implementations, so a language crate can ask the question without naming
//! `brokk-bifrost-analysis`'s resolution model.
//!
//! [`CodeUnitIndex`]: crate::analyzer::code_unit_index::CodeUnitIndex

use crate::CancellationToken;
use crate::analyzer::fq_name::FqName;
use crate::analyzer::model::{CodeUnit, Language, ProjectFile, SignatureMetadata};
use crate::path_utils::rel_path_string;

/// Deferred access to a [`BoundedDefinitionLookup`], handed to a graph source
/// instead of the index itself: the callback runs the consumer, so the index --
/// a handle that borrows the analyzer and merges one shard per delegate -- is
/// only materialized when a consumer actually asks a question. Every language
/// graph source takes the same shape, so it is declared once here.
pub type DefinitionLookupAccess<'a> =
    dyn Fn(&mut dyn FnMut(&dyn BoundedDefinitionLookup)) + Sync + 'a;

/// One mounted relational identity: a workspace-derived prefix plus the
/// content-derived tail persisted with a parsed blob.
///
/// Keeping the boundary explicit lets SQLite bind the two indexed identity
/// components without reparsing a rendered name or duplicating one content row
/// for every filesystem mount. A content-stable identity has an empty prefix;
/// the root package is represented by both components being empty.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RelationalName {
    prefix: FqName,
    tail: FqName,
}

impl RelationalName {
    pub fn new(prefix: FqName, tail: FqName) -> Self {
        Self { prefix, tail }
    }

    pub fn stable(name: FqName) -> Self {
        Self::new(FqName::new(), name)
    }

    pub fn prefix(&self) -> &FqName {
        &self.prefix
    }

    pub fn tail(&self) -> &FqName {
        &self.tail
    }

    pub fn full_name(&self) -> FqName {
        let mut full = self.prefix.clone();
        full.extend_from(&self.tail);
        full
    }

    pub fn is_empty(&self) -> bool {
        self.prefix.is_empty() && self.tail.is_empty()
    }
}

/// Languages visible to one relational request. `Workspace` is resolved by
/// the analysis-side executor from the analyzer's actual language set.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum DefinitionLanguageScope {
    Language(Language),
    Workspace,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PackageRelationKind {
    /// Whether at least one live workspace file belongs directly to this package.
    /// Ancestor-only hierarchy nodes are exposed through `Children` and
    /// `Descendants`, but do not satisfy this relation.
    Exists,
    Files,
    Children,
    Descendants,
}

/// The supported store query shapes. Every shape uses the request's structured
/// [`RelationalName`]; additional values are semantic leaves, never encoded
/// qualified names.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum RelationalDefinitionQuery {
    ExactName,
    NormalizedName,
    StructuralChildren,
    StructuralMembers {
        identifier: String,
    },
    VisibleMembers {
        identifier: String,
    },
    Identifier {
        file: Option<ProjectFile>,
    },
    /// Definitions whose persisted identifier begins with the name's terminal
    /// segment. This is an indexed half-open range used for source spellings
    /// with non-enumerable decorations, such as C# generic arity.
    IdentifierPrefix {
        file: Option<ProjectFile>,
    },
    PackageTypes {
        simple_name: String,
    },
    PackageTypesInPackage,
    PackageRelation(PackageRelationKind),
    CallableFacts,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RelationalDefinitionRequest {
    pub ordinal: usize,
    pub language_scope: DefinitionLanguageScope,
    pub name: RelationalName,
    pub query: RelationalDefinitionQuery,
}

/// One ordinal-free relational question used as a graph-resolution frontier key.
///
/// Graph passes may discover a later question only after an earlier answer is
/// known. Keeping the semantic question separate from batch publication order
/// lets a frontier record, batch, and replay those layers without making an
/// ordinal part of identity.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RelationalDefinitionQuestion {
    pub language_scope: DefinitionLanguageScope,
    pub name: RelationalName,
    pub query: RelationalDefinitionQuery,
}

impl RelationalDefinitionQuestion {
    pub fn request(&self, ordinal: usize) -> RelationalDefinitionRequest {
        RelationalDefinitionRequest {
            ordinal,
            language_scope: self.language_scope.clone(),
            name: self.name.clone(),
            query: self.query.clone(),
        }
    }
}

/// One callable signature and its typed metadata, read without resolving the
/// return identity into another workspace-wide materialization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelationalCallableFact {
    pub declaration: CodeUnit,
    pub signature_ordinal: usize,
    pub signature: String,
    pub metadata: Option<SignatureMetadata>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PackageRelationValue {
    Exists(bool),
    Files(Vec<ProjectFile>),
    Packages(Vec<String>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RelationalDefinitionValue {
    Definitions(Vec<CodeUnit>),
    PackageRelation(PackageRelationValue),
    CallableFacts(Vec<RelationalCallableFact>),
}

/// Read-only answers visible during one replayable resolution frontier.
///
/// An implementation returns the query shape's empty value while recording an
/// unanswered question. The frontier runner batches those questions, installs
/// their complete answers, and replays the owning computation. A real empty
/// answer is installed like any other answer, so absence converges rather than
/// causing another query on every replay.
pub trait RelationalDefinitionFrontier: Send + Sync {
    fn ask(&self, question: &RelationalDefinitionQuestion) -> RelationalDefinitionValue;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RelationalFrontierOutcome<T> {
    Complete(T),
    Cancelled,
    Failed(RelationalBatchError),
}

impl RelationalDefinitionValue {
    pub fn matches_query(&self, query: &RelationalDefinitionQuery) -> bool {
        matches!(
            (self, query),
            (
                Self::PackageRelation(PackageRelationValue::Exists(_)),
                RelationalDefinitionQuery::PackageRelation(PackageRelationKind::Exists)
            ) | (
                Self::PackageRelation(PackageRelationValue::Files(_)),
                RelationalDefinitionQuery::PackageRelation(PackageRelationKind::Files)
            ) | (
                Self::PackageRelation(PackageRelationValue::Packages(_)),
                RelationalDefinitionQuery::PackageRelation(
                    PackageRelationKind::Children | PackageRelationKind::Descendants
                )
            ) | (
                Self::CallableFacts(_),
                RelationalDefinitionQuery::CallableFacts
            ) | (
                Self::Definitions(_),
                RelationalDefinitionQuery::ExactName
                    | RelationalDefinitionQuery::NormalizedName
                    | RelationalDefinitionQuery::StructuralChildren
                    | RelationalDefinitionQuery::StructuralMembers { .. }
                    | RelationalDefinitionQuery::VisibleMembers { .. }
                    | RelationalDefinitionQuery::Identifier { .. }
                    | RelationalDefinitionQuery::IdentifierPrefix { .. }
                    | RelationalDefinitionQuery::PackageTypes { .. }
                    | RelationalDefinitionQuery::PackageTypesInPackage
            )
        )
    }

    /// The identity value for one query shape. Composite executors use this to
    /// merge language projections without giving absence a second encoding.
    pub fn empty_for(query: &RelationalDefinitionQuery) -> Self {
        match query {
            RelationalDefinitionQuery::PackageRelation(PackageRelationKind::Exists) => {
                Self::PackageRelation(PackageRelationValue::Exists(false))
            }
            RelationalDefinitionQuery::PackageRelation(PackageRelationKind::Files) => {
                Self::PackageRelation(PackageRelationValue::Files(Vec::new()))
            }
            RelationalDefinitionQuery::PackageRelation(
                PackageRelationKind::Children | PackageRelationKind::Descendants,
            ) => Self::PackageRelation(PackageRelationValue::Packages(Vec::new())),
            RelationalDefinitionQuery::CallableFacts => Self::CallableFacts(Vec::new()),
            _ => Self::Definitions(Vec::new()),
        }
    }

    /// Union another language projection into this value. The query shape is
    /// part of the request key, so unlike variants indicate an executor bug.
    pub fn merge_from(&mut self, other: Self) {
        match (self, other) {
            (Self::Definitions(left), Self::Definitions(right)) => left.extend(right),
            (Self::CallableFacts(left), Self::CallableFacts(right)) => left.extend(right),
            (
                Self::PackageRelation(PackageRelationValue::Exists(left)),
                Self::PackageRelation(PackageRelationValue::Exists(right)),
            ) => *left |= right,
            (
                Self::PackageRelation(PackageRelationValue::Files(left)),
                Self::PackageRelation(PackageRelationValue::Files(right)),
            ) => left.extend(right),
            (
                Self::PackageRelation(PackageRelationValue::Packages(left)),
                Self::PackageRelation(PackageRelationValue::Packages(right)),
            ) => left.extend(right),
            _ => panic!("a relational batch merged incompatible result shapes"),
        }
    }

    /// Publish the same deterministic set ordering whether one or many
    /// language projections contributed rows.
    pub fn canonicalize(&mut self) {
        match self {
            Self::Definitions(units) => {
                sort_units(units);
                units.dedup();
            }
            Self::CallableFacts(facts) => {
                facts.sort_by(|left, right| {
                    rel_path_string(left.declaration.source())
                        .cmp(&rel_path_string(right.declaration.source()))
                        .then_with(|| left.declaration.fq_name().cmp(&right.declaration.fq_name()))
                        .then_with(|| left.signature_ordinal.cmp(&right.signature_ordinal))
                });
                facts.dedup();
            }
            Self::PackageRelation(PackageRelationValue::Exists(_)) => {}
            Self::PackageRelation(PackageRelationValue::Files(files)) => {
                files.sort();
                files.dedup();
            }
            Self::PackageRelation(PackageRelationValue::Packages(packages)) => {
                packages.sort();
                packages.dedup();
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelationalDefinitionResult {
    pub ordinal: usize,
    pub value: RelationalDefinitionValue,
}

/// A store failure that is impossible to construct without useful context.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelationalBatchError(String);

impl RelationalBatchError {
    pub fn new(message: impl Into<String>) -> Self {
        let message = message.into();
        assert!(
            !message.trim().is_empty(),
            "a relational batch failure must explain the failure"
        );
        Self(message)
    }

    pub fn message(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RelationalBatchOutcome {
    Complete(Vec<RelationalDefinitionResult>),
    Cancelled,
    Failed(RelationalBatchError),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RelationalPointOutcome {
    Complete(RelationalDefinitionResult),
    Cancelled,
    Failed(RelationalBatchError),
}

/// Cross-crate boundary for definition-store questions. Language crates can
/// construct requests, while the analysis crate owns SQLite and implements the
/// executor.
pub trait RelationalDefinitionLookup {
    fn batch(
        &self,
        requests: &[RelationalDefinitionRequest],
        cancellation: &CancellationToken,
    ) -> RelationalBatchOutcome;

    /// A point request is exactly a batch of arity one.
    fn point(
        &self,
        request: &RelationalDefinitionRequest,
        cancellation: &CancellationToken,
    ) -> RelationalPointOutcome {
        match self.batch(std::slice::from_ref(request), cancellation) {
            RelationalBatchOutcome::Complete(mut results) => {
                assert_eq!(results.len(), 1, "an arity-one batch returns one result");
                RelationalPointOutcome::Complete(results.pop().unwrap())
            }
            RelationalBatchOutcome::Cancelled => RelationalPointOutcome::Cancelled,
            RelationalBatchOutcome::Failed(error) => RelationalPointOutcome::Failed(error),
        }
    }
}

pub trait BoundedDefinitionLookup {
    fn fqn(&self, fqn: &str) -> Vec<CodeUnit>;
    fn fqn_in_language(&self, fqn: &str, language: Language) -> Vec<CodeUnit>;

    /// Exact-fq lookup across *every* language the workspace indexes.
    ///
    /// A language-scoped resolver cannot tell "this fq is not in the workspace"
    /// apart from "this fq belongs to another language's declarations", so a
    /// confident cross-workspace boundary claim must consult this before it
    /// fires (#1174).  The default is the implementation's own scope: bounded
    /// single-language providers genuinely have no view of other languages, and
    /// answering same-language keeps them conservative (they can only *fail* to
    /// suppress a boundary claim, never invent a cross-language hit).
    fn fqn_in_any_language(&self, fqn: &str) -> Vec<CodeUnit> {
        self.fqn(fqn)
    }

    /// Language-blind counterpart of [`Self::package_exists`]; see
    /// [`Self::fqn_in_any_language`] for why the default is same-language.
    fn package_exists_in_any_language(&self, package: &str) -> bool {
        self.package_exists(package)
    }

    /// Types declared in `package` whose simple type name is `simple`.
    ///
    /// A secondary index over the workspace's declarations, so the default is
    /// the same conservative one [`Self::fqn_in_any_language`] takes: an
    /// implementation that answers through bounded store queries has no such
    /// index and reports nothing rather than guessing at a spelling.
    fn types_in_package(&self, _package: &str, _simple: &str) -> Vec<CodeUnit> {
        Vec::new()
    }

    /// Declarations whose fq name normalizes to `normalized`. Same secondary
    /// index, same default; see [`Self::types_in_package`].
    fn by_normalized_fqn(&self, _normalized: &str) -> Vec<CodeUnit> {
        Vec::new()
    }

    /// Declarations anywhere in the workspace whose simple identifier is
    /// `ident`. The file-scoped [`Self::file_identifier`] is the bounded
    /// question every implementation can answer; this is the workspace-wide
    /// one, so it takes the same conservative default as
    /// [`Self::types_in_package`].
    fn identifier(&self, _ident: &str) -> Vec<CodeUnit> {
        Vec::new()
    }

    /// Direct children of `owner_fqn` named `name`, falling back to the
    /// normalized spelling `normalized_owner_fqn` when the exact fq misses.
    ///
    /// Both spellings are supplied by the caller because normalization is
    /// language knowledge (C# strips generic arity, for instance) that the
    /// index itself does not have. Same secondary-index default as
    /// [`Self::types_in_package`].
    fn members_for_owner_name(
        &self,
        _owner_fqn: &str,
        _normalized_owner_fqn: &str,
        _name: &str,
    ) -> Vec<CodeUnit> {
        Vec::new()
    }

    /// Direct children of an already-resolved owner named `name`.
    ///
    /// Implementations with a structured definition relation should override
    /// this operation and preserve `owner.fq()` end to end. The rendered-name
    /// default keeps text-only bounded providers conservative without forcing
    /// them to reconstruct segment kinds they do not own.
    fn members_for_owner(&self, owner: &CodeUnit, name: &str) -> Vec<CodeUnit> {
        self.members_for_owner_name(&owner.fq_name(), &owner.fq_name(), name)
    }

    fn file_identifier(&self, file: &ProjectFile, ident: &str) -> Vec<CodeUnit>;
    fn fqn_direct_children(&self, fqn: &str) -> Vec<CodeUnit>;
    fn fqn_exists(&self, fqn: &str) -> bool;
    fn package_exists(&self, package: &str) -> bool;
    fn package_exists_in_language(&self, package: &str, language: Language) -> bool;
    fn fqn_prefix_exists(&self, prefix: &str) -> bool;

    fn fqn_candidates(&self, fqns: Vec<String>) -> Vec<CodeUnit> {
        let mut candidates = fqns
            .into_iter()
            .flat_map(|fqn| self.fqn(&fqn))
            .collect::<Vec<_>>();
        sort_units(&mut candidates);
        candidates.dedup();
        candidates
    }

    fn file_identifier_in_files(&self, files: &[ProjectFile], ident: &str) -> Vec<CodeUnit> {
        let mut out = Vec::new();
        for file in files {
            out.extend(self.file_identifier(file, ident));
        }
        sort_units(&mut out);
        out.dedup();
        out
    }
}

/// The canonical order definition-lookup results are published in: by source
/// path, then fq name, then signature, so a `dedup` after it collapses the
/// same declaration reached through two shards or two spellings.
pub fn sort_units(units: &mut [CodeUnit]) {
    units.sort_by(|left, right| {
        rel_path_string(left.source())
            .cmp(&rel_path_string(right.source()))
            .then_with(|| left.fq_name().cmp(&right.fq_name()))
            .then_with(|| left.signature().cmp(&right.signature()))
    });
}

#[cfg(test)]
mod relational_tests {
    use super::*;
    use crate::analyzer::fq_name::{SegmentKind, segment_interner};
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct EchoBatch {
        calls: AtomicUsize,
    }

    impl RelationalDefinitionLookup for EchoBatch {
        fn batch(
            &self,
            requests: &[RelationalDefinitionRequest],
            _cancellation: &CancellationToken,
        ) -> RelationalBatchOutcome {
            self.calls.fetch_add(1, Ordering::Relaxed);
            RelationalBatchOutcome::Complete(
                requests
                    .iter()
                    .map(|request| RelationalDefinitionResult {
                        ordinal: request.ordinal,
                        value: RelationalDefinitionValue::Definitions(Vec::new()),
                    })
                    .collect(),
            )
        }
    }

    fn request() -> RelationalDefinitionRequest {
        let mut name = FqName::new();
        name.push(segment_interner().intern("Widget", SegmentKind::Type));
        RelationalDefinitionRequest {
            ordinal: 17,
            language_scope: DefinitionLanguageScope::Language(Language::Java),
            name: RelationalName::stable(name),
            query: RelationalDefinitionQuery::ExactName,
        }
    }

    #[test]
    fn point_contract_delegates_to_one_batch_call() {
        let lookup = EchoBatch {
            calls: AtomicUsize::new(0),
        };
        assert_eq!(
            lookup.point(&request(), &CancellationToken::new()),
            RelationalPointOutcome::Complete(RelationalDefinitionResult {
                ordinal: 17,
                value: RelationalDefinitionValue::Definitions(Vec::new()),
            })
        );
        assert_eq!(lookup.calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    #[should_panic(expected = "must explain the failure")]
    fn batch_errors_cannot_be_empty() {
        let _ = RelationalBatchError::new("   ");
    }
}
