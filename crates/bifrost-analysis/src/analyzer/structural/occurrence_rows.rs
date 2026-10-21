//! The per-file occurrence derivation layer (#1473, Milestone 2).
//!
//! Milestone 1 taught the facts arena what each identifier token *is*; this
//! module turns those classifications into complete rows: range, class,
//! namespace, enclosing declaration, spelling, and — for reference-class rows —
//! the semantic target the definition resolver reports.
//!
//! Two properties are load-bearing:
//!
//! - Identity is structural. A row is addressed by `(content_identity, node)`,
//!   the same pair a structural capture can carry, so correlation is an
//!   equijoin on a digest rather than range or text coincidence.
//! - Nothing is guessed. Where the adapter cannot assign a namespace, the row
//!   is dropped and the file result records the role as incomplete; a consumer
//!   that asks about that role learns it cannot trust an empty answer.
//!
//! The rows are derived per request and never persisted (see the ExecPlan's
//! decision log); the facts snapshot underneath them is the cached part.

use super::facts::FileFacts;

use super::kinds::NormalizedKind;

use super::lexical_environment::BindingOfOutcome;
use super::lexical_environment::EnvironmentFileResult;
use super::lexical_environment::binding_of;
use super::lexical_environment::environment_for_file;

use super::occurrences::ALL_OCCURRENCE_ROLES;
use super::occurrences::Namespace;
use super::occurrences::OccurrenceClass;
use super::occurrences::OccurrenceRole;
use super::occurrences::OccurrenceRoleSupport;

use super::resolution::PrecedenceTier;
use super::resolution::RejectionReason;

use super::spec::StructuralSpec;

use crate::analyzer::common::language_for_file;

use crate::analyzer::lexical_definitions::LexicalDefinition;

use crate::analyzer::semantic::ContentIdentity;
use crate::analyzer::semantic::LengthDelimitedDigest;

use crate::analyzer::structural::StructuralFactProvider;

use crate::analyzer::structural_spec_for;

use crate::analyzer::usages::get_definition::DefinitionLookupRequest;
use crate::analyzer::usages::get_definition::DefinitionLookupStatus;
use crate::analyzer::usages::get_definition::ResolutionTraceResult;
use crate::analyzer::usages::get_definition::TraceCandidate;
use crate::analyzer::usages::get_definition::TraceCandidateRef;
use crate::analyzer::usages::get_definition::resolve_definition_batch_with_source_and_cancellation;
use crate::analyzer::usages::get_definition::resolve_definition_batch_with_trace;

use crate::analyzer::CodeUnit;
use crate::analyzer::IAnalyzer;
use crate::analyzer::ProjectFile;
use crate::analyzer::Range;

use crate::cancellation::CancellationToken;

use std::collections::HashSet;

use std::sync::Arc;

/// Domain separator for a single occurrence's stable id.
const OCCURRENCE_ID_DOMAIN: &[u8] = b"bifrost.code_query.occurrence.v1";

/// Domain separator for the AST-node id shared by occurrences and captures.
const AST_NODE_ID_DOMAIN: &[u8] = b"bifrost.code_query.ast_node.v1";

/// The content-scoped identity of one facts-arena node.
///
/// Both an occurrence row and a structural capture over the same node mint
/// this string, so equality of the two digests *is* the correlation join.
pub fn ast_id(content_identity: ContentIdentity, node: u32) -> String {
    let mut digest = LengthDelimitedDigest::new(AST_NODE_ID_DOMAIN);
    digest.push(content_identity.as_bytes());
    digest.push(&node.to_le_bytes());
    digest.finish().to_string()
}

/// The content-scoped identity of one occurrence row. A node classified with
/// two roles yields two distinguishable rows.
pub(crate) fn occurrence_id(
    content_identity: ContentIdentity,
    node: u32,
    role: OccurrenceRole,
) -> String {
    let mut digest = LengthDelimitedDigest::new(OCCURRENCE_ID_DOMAIN);
    push_occurrence_id_fields(&mut digest, content_identity, node, role);
    digest.finish().to_string()
}

/// Append the content, AST-node, and role fields shared by stable occurrence
/// and resolution-candidate identifiers. Callers supply their own digest
/// domain and any additional key fields.
#[doc(hidden)]
pub fn push_occurrence_id_fields(
    digest: &mut LengthDelimitedDigest,
    content_identity: ContentIdentity,
    node: u32,
    role: OccurrenceRole,
) {
    digest.push(content_identity.as_bytes());
    digest.push(&node.to_le_bytes());
    digest.push(role.label().as_bytes());
}

/// What a caller wants derived beyond the rows themselves.
///
/// Candidates are opt-in because they cost a second pass over the file's
/// lexical environment and force the definition batch to run with a trace
/// recorder installed. A caller that does not ask pays neither.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OccurrenceDerivationOptions {
    /// Attach the resolution trace to every reference-class row.
    pub candidates: bool,
    /// Resolve every reference-class row to the declarations it names.
    ///
    /// This is the definition batch, and it is by far the most expensive part
    /// of deriving a file's occurrences: one resolution per reference. A
    /// consumer that only needs each row's identity, role and position -- an
    /// assertion joining captures to occurrence rows, for example -- must not
    /// pay for it. Rows derived without it carry
    /// [`OccurrenceTarget::NotDerived`], which says "not attempted" and is
    /// never read as "resolved to nothing".
    pub targets: bool,
}

impl Default for OccurrenceDerivationOptions {
    fn default() -> Self {
        Self::ROWS_ONLY
    }
}

impl OccurrenceDerivationOptions {
    /// Rows with their resolved targets, without the resolution trace.
    pub const ROWS_ONLY: Self = Self {
        candidates: false,
        targets: true,
    };
    pub const WITH_CANDIDATES: Self = Self {
        candidates: true,
        targets: true,
    };
    /// Rows addressed by identity, role and position alone.
    pub const IDENTITY_ONLY: Self = Self {
        candidates: false,
        targets: false,
    };
}

/// One classified identifier position.
#[derive(Debug, Clone)]
pub struct OccurrenceRow {
    pub file: ProjectFile,
    pub content_identity: ContentIdentity,
    /// Facts-arena node id; the AST identity is `(content_identity, node)`.
    pub node: u32,
    pub range: Range,
    pub role: OccurrenceRole,
    pub class: OccurrenceClass,
    pub namespace: Namespace,
    pub enclosing: Option<CodeUnit>,
    /// Exact source slice of the node, never a re-scanned token boundary.
    pub raw_spelling: String,
    /// Present only when the adapter's decoding changes the spelling.
    pub decoded_spelling: Option<String>,
    /// The status of the definition lookup for a demanded reference row.
    /// `None` means resolution was not attempted, including undemanded rows,
    /// target-disabled derivation, and non-reference rows.
    pub resolution_status: Option<DefinitionLookupStatus>,
    pub target: OccurrenceTarget,
    /// The candidates the resolver considered for this reference, present only
    /// when the caller asked for them and only on reference-class rows. `None`
    /// means "not derived", never "none considered".
    pub candidates: Option<ResolutionTraceResult>,
}

impl OccurrenceRow {
    pub fn id(&self) -> String {
        occurrence_id(self.content_identity, self.node, self.role)
    }

    pub fn ast_id(&self) -> String {
        ast_id(self.content_identity, self.node)
    }

    /// The spelling a consumer should compare against a declared name.
    pub fn effective_spelling(&self) -> &str {
        self.decoded_spelling
            .as_deref()
            .unwrap_or(&self.raw_spelling)
    }
}

/// What a reference-class occurrence points at.
#[derive(Debug, Clone)]
pub enum OccurrenceTarget {
    /// Non-reference classes, which have nothing to resolve.
    None,
    /// Resolved; more than one unit means the resolution was ambiguous.
    Resolved(Vec<CodeUnit>),
    /// Resolved to a binder local to the file rather than to a declaration.
    Lexical(Box<LexicalDefinition>),
    /// Reference-class row whose resolution failed or stopped at a boundary.
    Unresolved(DefinitionLookupStatus),
    /// Reference-class row the caller did not ask to resolve.
    ///
    /// This is absence of an attempt, not absence of a target: a consumer must
    /// never read it as `Unresolved`. It exists so that skipping the
    /// definition batch stays visible in the row rather than being disguised
    /// as a resolution outcome.
    NotDerived,
}

/// Why a file's occurrence rows are less than the whole truth.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OccurrenceIncompleteReason {
    /// The adapter declares the role unsupported, so absence of rows for it
    /// says nothing about the file.
    RoleUnsupported(OccurrenceRole),
    /// The adapter classified tokens with this role but cannot say which
    /// namespace they resolve in, so those rows were dropped.
    NamespaceUnknown(OccurrenceRole),
    /// No structural adapter is registered for the file's language.
    NoStructuralAdapter,
    /// The analyzer holds no structural facts for the file.
    FactsUnavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OccurrenceCompleteness {
    Complete,
    Incomplete {
        unsupported_roles: Vec<OccurrenceRole>,
        reasons: Vec<OccurrenceIncompleteReason>,
    },
}

impl OccurrenceCompleteness {
    pub fn is_complete(&self) -> bool {
        matches!(self, Self::Complete)
    }

    /// Whether rows for `role` can be trusted to be the complete set.
    pub fn covers(&self, role: OccurrenceRole) -> bool {
        match self {
            Self::Complete => true,
            Self::Incomplete {
                unsupported_roles,
                reasons,
            } => {
                !unsupported_roles.contains(&role)
                    && !reasons.iter().any(|reason| match reason {
                        OccurrenceIncompleteReason::RoleUnsupported(unsupported)
                        | OccurrenceIncompleteReason::NamespaceUnknown(unsupported) => {
                            *unsupported == role
                        }
                        OccurrenceIncompleteReason::NoStructuralAdapter
                        | OccurrenceIncompleteReason::FactsUnavailable => true,
                    })
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct OccurrenceFileResult {
    pub rows: Vec<OccurrenceRow>,
    pub completeness: OccurrenceCompleteness,
}

/// The request was cancelled before the rows were complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OccurrencesCancelled;

/// Every occurrence row of one file, with an explicit account of what is
/// missing.
///
/// The source is taken from the facts snapshot rather than from the caller so
/// the rows, their spellings and their resolution requests are all addressed by
/// the same `ContentIdentity` the ids embed.
pub fn occurrences_for_file(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    cancellation: &CancellationToken,
) -> Result<OccurrenceFileResult, OccurrencesCancelled> {
    occurrences_for_file_with_options(
        analyzer,
        file,
        OccurrenceDerivationOptions::ROWS_ONLY,
        cancellation,
    )
}

/// [`occurrences_for_file`], with the derivation the caller wants.
///
/// With [`OccurrenceDerivationOptions::WITH_CANDIDATES`] every reference-class
/// row also carries the resolution trace: the candidates the resolver
/// considered, their tiers, their outcomes, and how far the lookup could see.
/// The `OccurrenceTarget` collapse is unchanged -- candidates are additive, and
/// no row's target moves because a caller asked for them.
pub fn occurrences_for_file_with_options(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    options: OccurrenceDerivationOptions,
    cancellation: &CancellationToken,
) -> Result<OccurrenceFileResult, OccurrencesCancelled> {
    occurrences_for_file_with_options_and_roles(analyzer, file, options, None, cancellation)
}

/// Query-local occurrence derivation restricted to the roles a typed seed can
/// observe.
///
/// The public per-file producer above remains exhaustive. A query with an
/// explicit role or class filter, however, cannot observe rows outside the
/// corresponding role set. Avoiding those rows also avoids their source
/// strings, enclosing-declaration lookups, and target resolutions. The result
/// retains the producer's complete role-support account, so an empty selected
/// role remains trustworthy only when the adapter proves it complete.
pub fn occurrences_for_file_with_options_and_roles(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    options: OccurrenceDerivationOptions,
    roles: Option<&[OccurrenceRole]>,
    cancellation: &CancellationToken,
) -> Result<OccurrenceFileResult, OccurrencesCancelled> {
    occurrences_for_file_scoped(analyzer, file, options, roles, None, None, cancellation)
}

/// Query-local occurrence derivation restricted to the exact AST identities a
/// correlated consumer will join.
///
/// The facts arena is still inspected to prove which requested identities
/// carry the requested roles, but source strings, enclosing declarations and
/// targets are materialized only for matching nodes. Completeness remains the
/// adapter's role-scoped account, so an absent requested identity is trusted
/// only when every requested role is covered.
#[doc(hidden)]
pub fn occurrences_for_file_with_options_roles_and_ast_ids(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    options: OccurrenceDerivationOptions,
    roles: &[OccurrenceRole],
    ast_ids: &HashSet<String>,
    cancellation: &CancellationToken,
) -> Result<OccurrenceFileResult, OccurrencesCancelled> {
    occurrences_for_file_scoped(
        analyzer,
        file,
        options,
        Some(roles),
        Some(ast_ids),
        None,
        cancellation,
    )
}

/// Resolve targets for an exact caller-selected set of rows from one file.
///
/// This keeps the same per-file definition batch as normal occurrence
/// derivation while allowing a query to finish its identity, role, name, and
/// structural filters before paying for target resolution. The supplied rows
/// are query-local clones; no target answer is retained by the analyzer.
#[doc(hidden)]
pub fn resolve_occurrence_targets_for_rows(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    rows: &mut [OccurrenceRow],
    cancellation: &CancellationToken,
) -> Result<(), OccurrencesCancelled> {
    if cancellation.is_cancelled() {
        return Err(OccurrencesCancelled);
    }
    if rows.is_empty() {
        return Ok(());
    }

    let language = language_for_file(file);
    let provider = analyzer
        .structural_fact_providers()
        .into_iter()
        .find(|provider| provider.structural_language() == language)
        .expect("occurrence rows have a structural fact provider");
    let facts = provider
        .structural_facts(file)
        .expect("occurrence rows have structural facts for their file");
    for row in rows.iter() {
        assert_eq!(row.file, *file, "one target batch contains one file");
        assert_eq!(
            row.content_identity,
            facts.source_identity(),
            "query-local occurrence rows and their facts share one content snapshot"
        );
    }

    resolve_reference_targets(
        analyzer,
        file,
        &facts,
        rows,
        OccurrenceDerivationOptions::ROWS_ONLY,
        None,
        cancellation,
    )
}

/// [`occurrences_for_file`], resolving targets only for reference rows that
/// start on one of `lines`.
///
/// Rows off those lines keep [`OccurrenceTarget::NotDerived`] ("not
/// attempted"), so a consumer that only probes specific sites -- the
/// usage-graph structural exact fallback reads its table at legacy call-site
/// lines -- pays the definition batch for exactly the rows it will read.
/// Classification, enclosing attachment, and the completeness account stay
/// exhaustive, so row identity is unchanged (issue #2679: resolving every
/// row of every file to serve a handful of site probes was the dominant cost
/// of review-sized diffs).
pub fn occurrences_for_file_at_lines(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    lines: &std::collections::BTreeSet<usize>,
    cancellation: &CancellationToken,
) -> Result<OccurrenceFileResult, OccurrencesCancelled> {
    occurrences_for_file_scoped(
        analyzer,
        file,
        OccurrenceDerivationOptions::ROWS_ONLY,
        None,
        None,
        Some(lines),
        cancellation,
    )
}

fn occurrences_for_file_scoped(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    options: OccurrenceDerivationOptions,
    roles: Option<&[OccurrenceRole]>,
    ast_ids: Option<&HashSet<String>>,
    lines: Option<&std::collections::BTreeSet<usize>>,
    cancellation: &CancellationToken,
) -> Result<OccurrenceFileResult, OccurrencesCancelled> {
    if cancellation.is_cancelled() {
        return Err(OccurrencesCancelled);
    }

    let language = language_for_file(file);
    let Some(spec) = structural_spec_for(language) else {
        return Ok(unavailable(OccurrenceIncompleteReason::NoStructuralAdapter));
    };
    let Some(provider) = analyzer
        .structural_fact_providers()
        .into_iter()
        .find(|provider| provider.structural_language() == language)
    else {
        return Ok(unavailable(OccurrenceIncompleteReason::FactsUnavailable));
    };
    let facts = provider.structural_facts(file);
    let Some(facts) = facts else {
        return Ok(unavailable(OccurrenceIncompleteReason::FactsUnavailable));
    };

    let support = spec.occurrence_role_support();
    let mut reasons: Vec<OccurrenceIncompleteReason> = ALL_OCCURRENCE_ROLES
        .iter()
        .copied()
        .filter(|role| !support.is_supported(*role))
        .map(OccurrenceIncompleteReason::RoleUnsupported)
        .collect();

    let mut rows = classify_rows(spec, file, &facts, roles, ast_ids, &mut reasons);
    if cancellation.is_cancelled() {
        return Err(OccurrencesCancelled);
    }
    attach_enclosing(provider, analyzer, file, &mut rows);
    if cancellation.is_cancelled() {
        return Err(OccurrencesCancelled);
    }
    resolve_reference_targets(
        analyzer,
        file,
        &facts,
        &mut rows,
        options,
        lines,
        cancellation,
    )?;

    Ok(OccurrenceFileResult {
        rows,
        completeness: completeness(support, reasons),
    })
}

fn unavailable(reason: OccurrenceIncompleteReason) -> OccurrenceFileResult {
    OccurrenceFileResult {
        rows: Vec::new(),
        completeness: OccurrenceCompleteness::Incomplete {
            unsupported_roles: ALL_OCCURRENCE_ROLES.to_vec(),
            reasons: vec![reason],
        },
    }
}

fn completeness(
    support: &OccurrenceRoleSupport,
    mut reasons: Vec<OccurrenceIncompleteReason>,
) -> OccurrenceCompleteness {
    if reasons.is_empty() {
        return OccurrenceCompleteness::Complete;
    }
    reasons.dedup();
    let unsupported_roles = ALL_OCCURRENCE_ROLES
        .iter()
        .copied()
        .filter(|role| !support.is_supported(*role))
        .collect();
    OccurrenceCompleteness::Incomplete {
        unsupported_roles,
        reasons,
    }
}

/// Walk the arena once, turning every classified token into a row.
fn classify_rows(
    spec: &dyn StructuralSpec,
    file: &ProjectFile,
    facts: &FileFacts,
    selected_roles: Option<&[OccurrenceRole]>,
    selected_ast_ids: Option<&HashSet<String>>,
    reasons: &mut Vec<OccurrenceIncompleteReason>,
) -> Vec<OccurrenceRow> {
    let content_identity = facts.source_identity();
    let source = facts.source();
    let mut rows = Vec::new();
    for node in 0..facts.nodes().len() {
        let node = u32::try_from(node).expect("facts arena node count fits in u32");
        let roles = facts.occurrence_roles(node);
        if roles.is_empty()
            || selected_roles
                .is_some_and(|selected| !roles.iter().any(|role| selected.contains(role)))
            || selected_ast_ids
                .is_some_and(|selected| !selected.contains(&ast_id(content_identity, node)))
        {
            continue;
        }
        let normalized = facts.node(node);
        let declared_kind = declared_fact_kind(facts, node);
        for &role in roles {
            if selected_roles.is_some_and(|selected| !selected.contains(&role)) {
                continue;
            }
            let Some(namespace) = spec.occurrence_namespace(role, declared_kind) else {
                let reason = OccurrenceIncompleteReason::NamespaceUnknown(role);
                if !reasons.contains(&reason) {
                    reasons.push(reason);
                }
                continue;
            };
            let raw_spelling =
                source[normalized.range.start_byte..normalized.range.end_byte].to_owned();
            let decoded_spelling = spec
                .decode_spelling(&raw_spelling)
                .filter(|decoded| decoded != &raw_spelling);
            rows.push(OccurrenceRow {
                file: file.clone(),
                content_identity,
                node,
                range: normalized.range,
                role,
                class: role.class(),
                namespace,
                enclosing: None,
                raw_spelling,
                decoded_spelling,
                resolution_status: None,
                target: OccurrenceTarget::None,
                candidates: None,
            });
        }
    }
    rows
}

/// The normalized kind of the fact this token *declares*, which is what a
/// declaration name inherits its namespace from.
///
/// This is the enclosing fact only when that fact's own recorded name span is
/// this token -- the arena's name pointer, not a range coincidence. The
/// distinction is load-bearing: a Rust struct field's name and a TypeScript
/// interface property's name are both children of a `Class` fact while naming
/// a value, so inheriting the container's kind would report them in the type
/// namespace.
pub(super) fn declared_fact_kind(facts: &FileFacts, node: u32) -> Option<NormalizedKind> {
    let normalized = facts.node(node);
    let parent = facts.node(normalized.parent?);
    (parent.name? == normalized.span()).then_some(parent.kind)
}

fn attach_enclosing(
    provider: &dyn StructuralFactProvider,
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    rows: &mut [OccurrenceRow],
) {
    let ranges = rows.iter().map(|row| row.range).collect::<Vec<_>>();
    if let Some(enclosures) = provider.structural_enclosing_code_units(file, &ranges) {
        assert_eq!(
            enclosures.len(),
            rows.len(),
            "structural enclosure providers must preserve the input cardinality"
        );
        for (row, enclosing) in rows.iter_mut().zip(enclosures) {
            row.enclosing = enclosing;
        }
        return;
    }
    for row in rows.iter_mut() {
        row.enclosing = analyzer.enclosing_code_unit(file, &row.range);
    }
}

/// One definition-resolution batch per file, the shape the LSP semantic-tokens
/// pass already uses, restricted to the rows whose class means "points at
/// something".
fn resolve_reference_targets(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    facts: &FileFacts,
    rows: &mut [OccurrenceRow],
    options: OccurrenceDerivationOptions,
    lines: Option<&std::collections::BTreeSet<usize>>,
    cancellation: &CancellationToken,
) -> Result<(), OccurrencesCancelled> {
    let (reference_indices, undemanded_indices): (Vec<usize>, Vec<usize>) = {
        let mut demanded = Vec::new();
        let mut undemanded = Vec::new();
        for (index, row) in rows.iter().enumerate() {
            if row.class != OccurrenceClass::Reference {
                continue;
            }
            if lines.is_none_or(|lines| lines.contains(&row.range.start_line)) {
                demanded.push(index);
            } else {
                undemanded.push(index);
            }
        }
        (demanded, undemanded)
    };
    // A row outside the caller's demanded lines is "not attempted", exactly
    // like the identity-only derivation below -- not "resolved to nothing".
    for &index in &undemanded_indices {
        rows[index].resolution_status = None;
        rows[index].target = OccurrenceTarget::NotDerived;
    }
    if !options.targets {
        // The caller asked for identity, role and position only. Say so in
        // every reference row rather than leaving `None`, which means "this
        // class has nothing to resolve" and would be a different claim.
        for &index in &reference_indices {
            rows[index].resolution_status = None;
            rows[index].target = OccurrenceTarget::NotDerived;
        }
        return Ok(());
    }
    if reference_indices.is_empty() {
        return Ok(());
    }

    let requests = reference_indices
        .iter()
        .map(|&index| DefinitionLookupRequest {
            file: file.clone(),
            line: None,
            column: None,
            start_byte: Some(rows[index].range.start_byte),
            end_byte: Some(rows[index].range.end_byte),
        })
        .collect();
    let source: Arc<str> = Arc::from(facts.source());
    let (outcomes, traces): (Vec<_>, Vec<_>) = if options.candidates {
        resolve_definition_batch_with_trace(analyzer, requests, file.clone(), source, cancellation)
            .into_iter()
            .map(|(outcome, trace)| (outcome, Some(trace)))
            .unzip()
    } else {
        (
            resolve_definition_batch_with_source_and_cancellation(
                analyzer,
                requests,
                file.clone(),
                source,
                cancellation,
            ),
            Vec::new(),
        )
    };
    if cancellation.is_cancelled() {
        return Err(OccurrencesCancelled);
    }
    assert_eq!(
        outcomes.len(),
        reference_indices.len(),
        "definition batch returned {} outcomes for {} reference rows",
        outcomes.len(),
        reference_indices.len()
    );

    // One environment per file, never per reference row: deriving it re-parses
    // the source the facts snapshot carries, so a per-row call would re-parse
    // the file once for every reference in it.
    let environment = options
        .candidates
        .then(|| environment_for_file(analyzer, file));

    for (position, &index) in reference_indices.iter().enumerate() {
        let outcome = &outcomes[position];
        rows[index].resolution_status = Some(outcome.status);
        rows[index].target = if !outcome.definitions.is_empty() {
            OccurrenceTarget::Resolved(outcome.definitions.clone())
        } else if let Some(lexical) = outcome.lexical_definition.clone() {
            OccurrenceTarget::Lexical(Box::new(lexical))
        } else {
            OccurrenceTarget::Unresolved(outcome.status)
        };
        if let Some(mut trace) = traces.get(position).cloned().flatten() {
            if let Some(environment) = environment.as_ref() {
                append_shadowed_bindings(environment, &rows[index], &mut trace);
            }
            rows[index].candidates = Some(trace);
        }
    }
    Ok(())
}

/// Add the bindings the lexical environment says are shadowed at this position.
///
/// The resolver's own lexical fast path stops at the nearest binder and never
/// enumerates the ones it passed, so the losers come from the binding-of
/// algorithm instead -- the same derivation, asked for the whole answer rather
/// than the winner. This is a producer consulting a producer, not the trace
/// re-deciding anything: the winner it reports must be the binder the resolver
/// already selected, and rows are added only when it is.
fn append_shadowed_bindings(
    environment: &EnvironmentFileResult,
    row: &OccurrenceRow,
    trace: &mut ResolutionTraceResult,
) {
    let OccurrenceTarget::Lexical(selected) = &row.target else {
        return;
    };
    let BindingOfOutcome::Shadowed { winner, shadowed } = binding_of(
        environment,
        row.effective_spelling(),
        row.range.start_byte,
        Some(row.namespace),
    ) else {
        return;
    };
    if environment.bindings[winner].range != selected.name_range {
        return;
    }
    trace.candidates.extend(shadowed.into_iter().map(|index| {
        let binding = &environment.bindings[index];
        TraceCandidate::rejected(
            TraceCandidateRef::Binding {
                file: binding.file.clone(),
                node: binding.node,
                name: binding.name.clone(),
            },
            Some(PrecedenceTier::LexicalBinding),
            RejectionReason::ShadowedByNearer,
        )
    }));
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
#[path = "occurrence_rows/js_ts_tests_support.rs"]
pub mod js_ts_tests_support;

#[cfg(test)]
mod tests {
    use super::js_ts_tests_support::*;

    use super::super::resolution::BoundaryStatus;
    use super::super::resolution::EnvironmentAxis;

    use super::*;

    use crate::analyzer::Language;

    use std::collections::BTreeSet;

    #[test]
    fn selected_reference_rows_keep_status_separate_from_undemanded_rows() {
        let source = concat!(
            "class Caller {\n",
            "    void first(Caller other) {\n",
            "        other.run();\n",
            "    }\n",
            "    void second(Caller other) {\n",
            "        other.run();\n",
            "    }\n",
            "    void run() {}\n",
            "}\n",
        );
        let fixture = Fixture::new(Language::Java, "src/Caller.java", source);
        let all = fixture.result();
        let demanded_line = all
            .rows
            .iter()
            .find(|row| {
                row.class == OccurrenceClass::Reference
                    && row.resolution_status == Some(DefinitionLookupStatus::Resolved)
            })
            .map(|row| row.range.start_line)
            .expect("fixture must contain a resolved reference row");
        let lines = BTreeSet::from([demanded_line]);
        let selected = occurrences_for_file_at_lines(
            fixture.workspace.analyzer(),
            &fixture.file,
            &lines,
            &CancellationToken::new(),
        )
        .expect("uncancelled selected occurrence derivation");

        let selected_references: Vec<_> = selected
            .rows
            .iter()
            .filter(|row| {
                row.class == OccurrenceClass::Reference && row.range.start_line == demanded_line
            })
            .collect();
        assert!(!selected_references.is_empty());
        assert!(
            selected_references
                .iter()
                .all(|row| row.resolution_status == Some(DefinitionLookupStatus::Resolved))
        );

        let undemanded_references: Vec<_> = selected
            .rows
            .iter()
            .filter(|row| {
                row.class == OccurrenceClass::Reference && row.range.start_line != demanded_line
            })
            .collect();
        assert!(
            !undemanded_references.is_empty(),
            "fixture must retain reference rows outside the demanded line"
        );
        assert!(undemanded_references.iter().all(|row| {
            row.resolution_status.is_none() && matches!(&row.target, OccurrenceTarget::NotDerived)
        }));
    }

    #[test]
    fn java_declaration_heads_carry_type_namespaces_and_reads_resolve() {
        let source = concat!(
            "package app;\n",
            "class Widget {\n",
            "    static int SIZE = 2;\n",
            "    int render(String label) {\n",
            "        return label.length() + SIZE;\n",
            "    }\n",
            "}\n",
        );
        let fixture = Fixture::new(Language::Java, "app/Widget.java", source);
        let result = fixture.result();

        let class_name = expect_row(&result.rows, fixture.at("Widget {"), "class name");
        assert_eq!(class_name.role, OccurrenceRole::DeclarationName);
        assert_eq!(class_name.class, OccurrenceClass::Declaration);
        assert_eq!(class_name.namespace, Namespace::Type);
        assert_eq!(class_name.raw_spelling, "Widget");
        assert!(matches!(class_name.target, OccurrenceTarget::None));

        let method_name = expect_row(&result.rows, fixture.at("render(String"), "method name");
        assert_eq!(method_name.role, OccurrenceRole::DeclarationName);
        assert_eq!(method_name.namespace, Namespace::Value);

        let parameter = expect_row(&result.rows, fixture.at("label)"), "parameter binder");
        assert_eq!(parameter.role, OccurrenceRole::Binder);
        assert_eq!(parameter.class, OccurrenceClass::Binding);
        assert!(matches!(parameter.target, OccurrenceTarget::None));

        let read = expect_row(&result.rows, fixture.at("label.length"), "receiver read");
        assert_eq!(read.role, OccurrenceRole::ReceiverPosition);
        assert_eq!(read.class, OccurrenceClass::Reference);
        assert!(
            matches!(
                read.target,
                OccurrenceTarget::Resolved(_) | OccurrenceTarget::Lexical(_)
            ),
            "receiver read should resolve to the parameter, got {:?}",
            read.target
        );
        assert_eq!(
            read.enclosing.as_ref().map(CodeUnit::fq_name),
            fixture
                .workspace
                .analyzer()
                .enclosing_code_unit(&fixture.file, &read.range)
                .as_ref()
                .map(CodeUnit::fq_name)
        );
    }

    /// Issue #1569, shape 1: a bare read of a local variable resolves to its
    /// binder as a lexical definition, not `Unresolved(NoDefinition)`. The
    /// shadowing spelling proves the same claim when the name collides with an
    /// indexed type.
    #[test]
    fn java_bare_local_reads_resolve_to_the_local_binder_lexically() {
        let source = concat!(
            "class Widget {\n",
            "    int plain() {\n",
            "        int local = 1;\n",
            "        return local;\n",
            "    }\n",
            "    int shadowing() {\n",
            "        int Config = 1;\n",
            "        return Config;\n",
            "    }\n",
            "}\n",
        );
        let fixture = Fixture::with_supporting_files(
            Language::Java,
            "app/Widget.java",
            source,
            &[(
                "app/Config.java",
                "class Config {\n    static int LIMIT = 7;\n}\n",
            )],
        );
        let result = fixture.result();

        let plain_read = expect_row(&result.rows, fixture.at("local;"), "plain local read");
        assert_eq!(plain_read.class, OccurrenceClass::Reference);
        match &plain_read.target {
            OccurrenceTarget::Lexical(definition) => {
                assert_eq!(definition.identifier, "local");
                assert_eq!(definition.name_range.start_byte, fixture.at("local = 1"));
            }
            other => panic!("bare local read should resolve lexically, got {other:?}"),
        }

        let shadowing_read = expect_row(&result.rows, fixture.at("Config;"), "shadowing read");
        match &shadowing_read.target {
            OccurrenceTarget::Lexical(definition) => {
                assert_eq!(definition.identifier, "Config");
                assert_eq!(definition.name_range.start_byte, fixture.at("Config = 1"));
            }
            other => panic!("shadowed local read should resolve lexically, got {other:?}"),
        }
    }

    /// Issue #1569, shape 2: the member position of a static field access
    /// resolves to the indexed field even when a sibling scope binds a local
    /// with the qualifier's spelling.
    #[test]
    fn java_static_field_member_position_resolves_to_the_indexed_field() {
        let source = concat!(
            "class Caller {\n",
            "    int shadow() {\n",
            "        int Config = 1;\n",
            "        return Config;\n",
            "    }\n",
            "    int use() {\n",
            "        return Config.LIMIT;\n",
            "    }\n",
            "}\n",
        );
        let fixture = Fixture::with_supporting_files(
            Language::Java,
            "app/Caller.java",
            source,
            &[(
                "app/Config.java",
                "class Config {\n    static int LIMIT = 7;\n}\n",
            )],
        );
        let result = fixture.result();

        let member = expect_row(&result.rows, fixture.at("LIMIT;"), "static field member");
        assert_eq!(member.class, OccurrenceClass::Reference);
        match &member.target {
            OccurrenceTarget::Resolved(units) => assert!(
                units
                    .iter()
                    .all(|unit| unit.fq_name().contains("Config.LIMIT") && unit.is_field()),
                "the member must resolve to the static field: {units:?}"
            ),
            other => panic!("static field member should resolve to the field, got {other:?}"),
        }
    }

    /// The regression shape from the issue: a qualified static read must
    /// resolve to the static field, not to the local that shadows its name.
    #[test]
    fn java_static_qualifier_resolves_to_the_static_target_not_the_local() {
        let source = concat!(
            "class Caller {\n",
            // A local that shares the type's spelling, in a sibling scope: the
            // qualifier below must not be captured by it.
            "    int shadow() {\n",
            "        int Config = 1;\n",
            "        return Config;\n",
            "    }\n",
            "    int use() {\n",
            "        return Config.LIMIT;\n",
            "    }\n",
            "}\n",
        );
        let fixture = Fixture::with_supporting_files(
            Language::Java,
            "app/Caller.java",
            source,
            &[(
                "app/Config.java",
                "class Config {\n    static int LIMIT = 7;\n}\n",
            )],
        );
        let result = fixture.result();

        let qualifier = expect_row(&result.rows, fixture.at("Config.LIMIT"), "static qualifier");
        assert_eq!(qualifier.role, OccurrenceRole::ReceiverPosition);
        match &qualifier.target {
            OccurrenceTarget::Resolved(units) => assert!(
                units
                    .iter()
                    .all(|unit| unit.fq_name().contains("Config") && unit.is_class()),
                "the qualifier must resolve to the type, not the sibling local: {units:?}"
            ),
            other => panic!("static qualifier should resolve to the type, got {other:?}"),
        }

        let shadowing_local =
            expect_row(&result.rows, fixture.at("Config;"), "shadowing local read");
        assert!(
            !matches!(shadowing_local.target, OccurrenceTarget::Resolved(_)),
            "a local read must not borrow the type's resolution: {:?}",
            shadowing_local.target
        );
    }

    /// Java resolves a simple type name against single-type imports before
    /// on-demand ones, so an explicit import selects at its tier and the
    /// wildcard routes it beat are recorded as rejected peers.
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "0242909d77ed: Java census G04 native traces omitted winning import tiers and defeated wildcard routes"
    )]
    fn an_explicit_java_import_selects_over_the_wildcard_routes_it_beat() {
        let source = concat!(
            "package app;\n",
            "import app.model.Widget;\n",
            "import app.other.*;\n",
            "class Caller {\n",
            "    Widget build() { return null; }\n",
            "}\n",
        );
        let fixture = Fixture::with_supporting_files(
            Language::Java,
            "app/Caller.java",
            source,
            &[
                (
                    "app/model/Widget.java",
                    "package app.model;\npublic class Widget {}\n",
                ),
                (
                    "app/other/Widget.java",
                    "package app.other;\npublic class Widget {}\n",
                ),
            ],
        );
        let result = fixture.traced_result();
        let trace = trace_of(&result.rows, fixture.at("Widget build"), "return type");

        assert!(
            trace.selects_at(PrecedenceTier::ExplicitImport),
            "the single-type import is the winning tier: {:?}",
            trace.candidates
        );
        let wildcard: Vec<_> = trace
            .rejected()
            .filter(|row| row.tier == Some(PrecedenceTier::WildcardImport))
            .collect();
        assert_eq!(
            wildcard.len(),
            1,
            "the one on-demand import is the rejected peer: {:?}",
            trace.candidates
        );
        assert_eq!(
            wildcard[0].outcome.rejection(),
            Some(RejectionReason::ShadowedByNearer)
        );
        match &wildcard[0].candidate {
            // An on-demand import binds no single name, so the route keeps the
            // wildcard marker as its name -- and states the package it pointed
            // at through the parser-derived target segments (#1600).
            TraceCandidateRef::ImportBinder {
                name,
                target_segments,
                ..
            } => {
                assert_eq!(
                    name,
                    crate::analyzer::usages::get_definition::trace::WILDCARD_ROUTE_NAME
                );
                assert_eq!(
                    target_segments,
                    &["app".to_string(), "other".to_string()],
                    "the rejected route names the package its wildcard covered"
                );
            }
            other => panic!("a rejected import route is an import binder, got {other:?}"),
        }
    }

    /// A reference that leaves the workspace reports how far the lookup could
    /// see, and never reports a selection at the fallback tier the anti-fallback
    /// contract forbids.
    #[test]
    fn a_boundary_reference_reports_its_boundary_and_never_a_name_only_fallback() {
        let source = concat!(
            "package app;\n",
            "import com.absent.Gadget;\n",
            "class Caller {\n",
            "    Gadget build() { return null; }\n",
            "}\n",
        );
        let fixture = Fixture::new(Language::Java, "app/Caller.java", source);
        let result = fixture.traced_result();
        let trace = trace_of(&result.rows, fixture.at("Gadget build"), "external type");

        let external: Vec<_> = trace
            .candidates
            .iter()
            .filter(|row| matches!(row.candidate, TraceCandidateRef::ExternalRoute { .. }))
            .collect();
        assert!(
            !external.is_empty(),
            "a boundary outcome always reports the route it took: {:?}",
            trace.candidates
        );
        assert!(
            external
                .iter()
                .all(|row| row.boundary != BoundaryStatus::WorkspaceLocal),
            "a boundary row is by definition not workspace-local: {external:?}"
        );
        assert!(
            !trace.selects_at(PrecedenceTier::NameOnlyFallback),
            "nothing may be selected at the forbidden fallback tier: {:?}",
            trace.candidates
        );
    }

    /// An adapter that has not learned the candidate axes must surface that
    /// through the capability spine. An empty trace from an uninstrumented
    /// language would read exactly like "the resolver considered nothing".
    ///
    /// Scala classifies occurrence roles since #1597, so the rows themselves
    /// are real; what it still does not do is record a considered set, and
    /// that is what the axes and the trace completeness must keep saying.
    #[test]
    fn an_uninstrumented_language_reports_the_candidate_axes_unsupported() {
        let fixture = Fixture::new(
            Language::Scala,
            "src/app.scala",
            "class Widget { def render(label: String): String = label }\n",
        );
        let support = crate::analyzer::structural_spec_for(Language::Scala)
            .expect("Scala has a structural adapter")
            .lexical_environment_support();
        assert!(
            !support.is_supported(EnvironmentAxis::CandidateSelection),
            "Scala must not claim a selection axis it does not answer"
        );
        assert!(!support.is_supported(EnvironmentAxis::CandidateRejection));

        let result = fixture.traced_result();
        assert!(
            !result.rows.is_empty(),
            "Scala classifies occurrence roles, so the rows are real"
        );
        assert!(
            result
                .rows
                .iter()
                .filter_map(|row| row.candidates.as_ref())
                .all(|trace| !trace.completeness.covers_rejections()),
            "a language that claims neither candidate axis must never publish a considered set: {:?}",
            result.rows
        );
    }

    #[test]
    fn ids_are_content_scoped_and_role_scoped() {
        let content = ContentIdentity::hash_bytes(b"class Widget {}");
        let other = ContentIdentity::hash_bytes(b"class Gadget {}");

        assert_eq!(
            occurrence_id(content, 3, OccurrenceRole::Binder),
            occurrence_id(content, 3, OccurrenceRole::Binder)
        );
        assert_ne!(
            occurrence_id(content, 3, OccurrenceRole::Binder),
            occurrence_id(other, 3, OccurrenceRole::Binder)
        );
        assert_ne!(
            occurrence_id(content, 3, OccurrenceRole::Binder),
            occurrence_id(content, 4, OccurrenceRole::Binder)
        );
        assert_ne!(
            occurrence_id(content, 3, OccurrenceRole::Binder),
            occurrence_id(content, 3, OccurrenceRole::ValueReference)
        );

        assert_eq!(ast_id(content, 3), ast_id(content, 3));
        assert_ne!(ast_id(content, 3), ast_id(other, 3));
        assert_ne!(
            ast_id(content, 3),
            occurrence_id(content, 3, OccurrenceRole::Binder),
            "the two domains must not collide"
        );
    }
}
