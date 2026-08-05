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
use super::lexical_environment::{
    EnvironmentFileResult, ReachingBindingOutcome, environment_for_file, reaching_binding,
};
use super::occurrences::{
    ALL_OCCURRENCE_ROLES, Namespace, OccurrenceClass, OccurrenceRole, OccurrenceRoleSupport,
};
use super::resolution::{PrecedenceTier, RejectionReason};
use super::spec::StructuralSpec;
use crate::analyzer::common::language_for_file;
use crate::analyzer::lexical_definitions::LexicalDefinition;
use crate::analyzer::semantic::{ContentIdentity, LengthDelimitedDigest};
use crate::analyzer::structural_spec_for;
use crate::analyzer::usages::get_definition::{
    DefinitionLookupRequest, DefinitionLookupStatus, ResolutionTraceResult, TraceCandidate,
    TraceCandidateRef, resolve_definition_batch_with_source_and_cancellation,
    resolve_definition_batch_with_trace,
};
use crate::analyzer::{CodeUnit, IAnalyzer, ProjectFile, Range};
use crate::cancellation::CancellationToken;
use std::sync::Arc;

/// Domain separator for a single occurrence's stable id.
const OCCURRENCE_ID_DOMAIN: &[u8] = b"bifrost.code_query.occurrence.v1";

/// Domain separator for the AST-node id shared by occurrences and captures.
const AST_NODE_ID_DOMAIN: &[u8] = b"bifrost.code_query.ast_node.v1";

/// The content-scoped identity of one facts-arena node.
///
/// Both an occurrence row and a structural capture over the same node mint
/// this string, so equality of the two digests *is* the correlation join.
pub(crate) fn ast_id(content_identity: ContentIdentity, node: u32) -> String {
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
    digest.push(content_identity.as_bytes());
    digest.push(&node.to_le_bytes());
    digest.push(role.label().as_bytes());
    digest.finish().to_string()
}

/// What a caller wants derived beyond the rows themselves.
///
/// Candidates are opt-in because they cost a second pass over the file's
/// lexical environment and force the definition batch to run with a trace
/// recorder installed. A caller that does not ask pays neither.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OccurrenceDerivationOptions {
    /// Attach the resolution trace to every reference-class row.
    pub candidates: bool,
}

impl OccurrenceDerivationOptions {
    pub const ROWS_ONLY: Self = Self { candidates: false };
    pub const WITH_CANDIDATES: Self = Self { candidates: true };
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
    if cancellation.is_cancelled() {
        return Err(OccurrencesCancelled);
    }

    let language = language_for_file(file);
    let Some(spec) = structural_spec_for(language) else {
        return Ok(unavailable(OccurrenceIncompleteReason::NoStructuralAdapter));
    };
    let facts = analyzer
        .structural_search_providers()
        .into_iter()
        .find(|provider| provider.structural_language() == language)
        .and_then(|provider| provider.structural_facts(file));
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

    let mut rows = classify_rows(spec, file, &facts, &mut reasons);
    if cancellation.is_cancelled() {
        return Err(OccurrencesCancelled);
    }
    attach_enclosing(analyzer, file, &mut rows);
    if cancellation.is_cancelled() {
        return Err(OccurrencesCancelled);
    }
    resolve_reference_targets(analyzer, file, &facts, &mut rows, options, cancellation)?;

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
    reasons: &mut Vec<OccurrenceIncompleteReason>,
) -> Vec<OccurrenceRow> {
    let content_identity = facts.source_identity();
    let source = facts.source();
    let mut rows = Vec::new();
    for node in 0..facts.nodes().len() {
        let node = u32::try_from(node).expect("facts arena node count fits in u32");
        let roles = facts.occurrence_roles(node);
        if roles.is_empty() {
            continue;
        }
        let normalized = facts.node(node);
        let declared_kind = declared_fact_kind(facts, node);
        for &role in roles {
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
fn declared_fact_kind(facts: &FileFacts, node: u32) -> Option<NormalizedKind> {
    let normalized = facts.node(node);
    let parent = facts.node(normalized.parent?);
    (parent.name? == normalized.span()).then_some(parent.kind)
}

fn attach_enclosing(analyzer: &dyn IAnalyzer, file: &ProjectFile, rows: &mut [OccurrenceRow]) {
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
    cancellation: &CancellationToken,
) -> Result<(), OccurrencesCancelled> {
    let reference_indices: Vec<usize> = rows
        .iter()
        .enumerate()
        .filter(|(_, row)| row.class == OccurrenceClass::Reference)
        .map(|(index, _)| index)
        .collect();
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
/// enumerates the ones it passed, so the losers come from the reaching-binding
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
    let ReachingBindingOutcome::Shadowed { winner, shadowed } = reaching_binding(
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

#[cfg(test)]
mod tests {
    use super::super::resolution::{BoundaryStatus, EnvironmentAxis};
    use super::*;
    use crate::analyzer::usages::get_definition::TraceCompleteness;
    use crate::analyzer::{AnalyzerConfig, Language, Project, TestProject, WorkspaceAnalyzer};
    use std::path::PathBuf;
    use tempfile::TempDir;

    struct Fixture {
        _temp: TempDir,
        workspace: WorkspaceAnalyzer,
        file: ProjectFile,
        source: String,
    }

    impl Fixture {
        fn new(language: Language, relative_path: &str, source: &str) -> Self {
            Self::with_supporting_files(language, relative_path, source, &[])
        }

        /// A fixture whose occurrences are read from `relative_path` while the
        /// analyzer also indexes `supporting`, so cross-file resolution has
        /// something to resolve to.
        fn with_supporting_files(
            language: Language,
            relative_path: &str,
            source: &str,
            supporting: &[(&str, &str)],
        ) -> Self {
            let temp = tempfile::tempdir().expect("temp dir");
            let root: PathBuf = temp.path().canonicalize().expect("canonical root");
            let file = ProjectFile::new(root.clone(), relative_path);
            file.write(source).expect("write fixture source");
            for (path, contents) in supporting {
                ProjectFile::new(root.clone(), *path)
                    .write(contents)
                    .expect("write supporting source");
            }
            let project = TestProject::new(root, language);
            let workspace = WorkspaceAnalyzer::build(
                Arc::new(project) as Arc<dyn Project>,
                AnalyzerConfig::default(),
            );
            Self {
                _temp: temp,
                workspace,
                file,
                source: source.to_owned(),
            }
        }

        fn result(&self) -> OccurrenceFileResult {
            occurrences_for_file(
                self.workspace.analyzer(),
                &self.file,
                &CancellationToken::new(),
            )
            .expect("uncancelled occurrence derivation")
        }

        fn traced_result(&self) -> OccurrenceFileResult {
            occurrences_for_file_with_options(
                self.workspace.analyzer(),
                &self.file,
                OccurrenceDerivationOptions::WITH_CANDIDATES,
                &CancellationToken::new(),
            )
            .expect("uncancelled occurrence derivation")
        }

        /// Byte offset of `needle`, whose first token is the occurrence under
        /// test; the marker keeps the assertion readable without re-scanning.
        fn at(&self, needle: &str) -> usize {
            self.source
                .find(needle)
                .unwrap_or_else(|| panic!("fixture does not contain {needle:?}"))
        }
    }

    fn row_at(rows: &[OccurrenceRow], start_byte: usize) -> Option<&OccurrenceRow> {
        rows.iter().find(|row| row.range.start_byte == start_byte)
    }

    fn expect_row<'rows>(
        rows: &'rows [OccurrenceRow],
        start_byte: usize,
        label: &str,
    ) -> &'rows OccurrenceRow {
        row_at(rows, start_byte).unwrap_or_else(|| {
            panic!(
                "no occurrence row for {label} at byte {start_byte}; rows: {:?}",
                rows.iter()
                    .map(|row| (row.range.start_byte, row.raw_spelling.as_str(), row.role))
                    .collect::<Vec<_>>()
            )
        })
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

    #[test]
    fn js_shorthand_is_a_binder_in_a_pattern_and_a_reference_in_an_expression() {
        let source = concat!(
            "const source = { alpha: 1, beta: 2 };\n",
            "const { alpha, beta: renamed } = source;\n",
            "const payload = { alpha };\n",
        );
        let fixture = Fixture::new(Language::JavaScript, "src/app.js", source);
        let result = fixture.result();

        let pattern_binder = expect_row(&result.rows, fixture.at("alpha, beta"), "pattern binder");
        assert_eq!(pattern_binder.role, OccurrenceRole::Binder);
        assert_eq!(pattern_binder.class, OccurrenceClass::Binding);
        assert_eq!(pattern_binder.namespace, Namespace::Value);
        assert!(matches!(pattern_binder.target, OccurrenceTarget::None));

        let renamed_key = expect_row(&result.rows, fixture.at("beta: renamed"), "renamed key");
        assert_eq!(renamed_key.role, OccurrenceRole::LabelOrKey);
        assert_eq!(renamed_key.namespace, Namespace::Label);
        let renamed_binder = expect_row(&result.rows, fixture.at("renamed }"), "renamed binder");
        assert_eq!(renamed_binder.role, OccurrenceRole::Binder);

        let shorthand_read = expect_row(&result.rows, fixture.at("alpha };"), "shorthand read");
        assert_eq!(shorthand_read.role, OccurrenceRole::ValueReference);
        assert_eq!(shorthand_read.class, OccurrenceClass::Reference);
        assert!(
            !matches!(shorthand_read.target, OccurrenceTarget::None),
            "reference-class rows always carry a resolution outcome"
        );
    }

    #[test]
    fn typescript_keyed_fields_and_type_operands_stay_apart() {
        let source = concat!(
            "interface Widget { label: string }\n",
            "const table = { label: \"a\" };\n",
            "function render(widget: Widget): string {\n",
            "    return widget.label + table.label;\n",
            "}\n",
        );
        let fixture = Fixture::new(Language::TypeScript, "src/app.ts", source);
        let result = fixture.result();

        let map_key = expect_row(&result.rows, fixture.at("label: \"a\""), "map key");
        assert_eq!(map_key.role, OccurrenceRole::LabelOrKey);
        assert_eq!(map_key.namespace, Namespace::Label);
        assert_eq!(map_key.class, OccurrenceClass::NonReference);

        let type_operand = expect_row(&result.rows, fixture.at("Widget)"), "annotation operand");
        assert_eq!(type_operand.role, OccurrenceRole::TypeOperand);
        assert_eq!(type_operand.namespace, Namespace::Type);

        let binder = expect_row(&result.rows, fixture.at("widget: Widget"), "parameter");
        assert_eq!(binder.role, OccurrenceRole::Binder);
        assert_eq!(binder.namespace, Namespace::Value);

        let member = expect_row(&result.rows, fixture.at("label + table"), "member read");
        assert_eq!(member.role, OccurrenceRole::MemberPosition);
        assert_eq!(member.class, OccurrenceClass::Reference);
    }

    #[test]
    fn python_annotations_are_type_operands_and_parameters_are_binders() {
        let source = concat!(
            "import os.path\n",
            "\n",
            "class Widget:\n",
            "    def render(self, label: str) -> str:\n",
            "        return os.path.join(label, key=label)\n",
        );
        let fixture = Fixture::new(Language::Python, "src/app.py", source);
        let result = fixture.result();

        let class_name = expect_row(&result.rows, fixture.at("Widget:"), "class name");
        assert_eq!(class_name.namespace, Namespace::Type);

        let binder = expect_row(&result.rows, fixture.at("label: str"), "parameter binder");
        assert_eq!(binder.role, OccurrenceRole::Binder);
        assert_eq!(binder.namespace, Namespace::Value);

        let annotation = expect_row(&result.rows, fixture.at("str)"), "annotation operand");
        assert_eq!(annotation.role, OccurrenceRole::TypeOperand);
        assert_eq!(annotation.namespace, Namespace::Type);

        let segment = expect_row(&result.rows, fixture.at("os.path\n"), "import path segment");
        assert_eq!(segment.role, OccurrenceRole::PathSegment);
        assert_eq!(
            segment.namespace,
            Namespace::Module,
            "Python dotted-name segments are modules"
        );

        let keyword = expect_row(&result.rows, fixture.at("key="), "keyword argument name");
        assert_eq!(keyword.role, OccurrenceRole::LabelOrKey);
        assert_eq!(keyword.namespace, Namespace::Label);
    }

    #[test]
    fn rust_raw_identifiers_decode_and_declaration_heads_keep_their_namespace() {
        let source = concat!(
            "struct Widget {\n",
            "    label: String,\n",
            "}\n",
            "\n",
            "fn render(r#type: &str) -> String {\n",
            "    r#type.to_owned()\n",
            "}\n",
        );
        let fixture = Fixture::new(Language::Rust, "src/app.rs", source);
        let result = fixture.result();

        let struct_name = expect_row(&result.rows, fixture.at("Widget {"), "struct name");
        assert_eq!(struct_name.role, OccurrenceRole::DeclarationName);
        assert_eq!(struct_name.namespace, Namespace::Type);

        let function_name = expect_row(&result.rows, fixture.at("render("), "function name");
        assert_eq!(function_name.namespace, Namespace::Value);

        let raw_binder = expect_row(&result.rows, fixture.at("r#type:"), "raw-identifier binder");
        assert_eq!(raw_binder.role, OccurrenceRole::Binder);
        assert_eq!(raw_binder.raw_spelling, "r#type");
        assert_eq!(raw_binder.decoded_spelling.as_deref(), Some("type"));
        assert_eq!(raw_binder.effective_spelling(), "type");

        let plain = expect_row(&result.rows, fixture.at("label: String"), "field name");
        assert_eq!(
            plain.decoded_spelling, None,
            "unescaped spellings decode to nothing"
        );
    }

    /// A declaration name inherits the namespace of the fact it *names*, not of
    /// the fact it sits inside. `field_declaration` is not itself a fact, so a
    /// Rust struct field's name has a `Class` fact for its arena parent while
    /// naming a value; inheriting the parent's kind would report a field in the
    /// type namespace. The same shape occurs for a TypeScript interface member.
    #[test]
    fn a_member_name_under_a_type_declaration_stays_in_the_value_namespace() {
        let rust = Fixture::new(
            Language::Rust,
            "src/app.rs",
            "struct Widget {\n    label: String,\n}\n",
        );
        let rust_result = rust.result();
        assert_eq!(
            expect_row(&rust_result.rows, rust.at("Widget {"), "struct name").namespace,
            Namespace::Type,
            "the struct's own name is the one token that names the type"
        );
        assert_eq!(
            expect_row(&rust_result.rows, rust.at("label: String"), "field name").namespace,
            Namespace::Value
        );

        let typescript = Fixture::new(
            Language::TypeScript,
            "src/app.ts",
            "interface Widget {\n    label: string;\n}\n",
        );
        let typescript_result = typescript.result();
        assert_eq!(
            expect_row(
                &typescript_result.rows,
                typescript.at("Widget {"),
                "interface name"
            )
            .namespace,
            Namespace::Type
        );
        assert_eq!(
            expect_row(
                &typescript_result.rows,
                typescript.at("label: string"),
                "property name"
            )
            .namespace,
            Namespace::Value
        );
    }

    /// Rust cannot say whether a path scope segment is a module or a type, so
    /// those rows are dropped and the role is reported incomplete rather than
    /// being silently guessed into the value namespace.
    #[test]
    fn rust_path_segments_are_dropped_and_reported_rather_than_guessed() {
        let source = "use std::collections::HashMap;\nfn take(map: HashMap<u32, u32>) -> usize { map.len() }\n";
        let fixture = Fixture::new(Language::Rust, "src/app.rs", source);
        let result = fixture.result();

        assert!(
            !result
                .rows
                .iter()
                .any(|row| row.role == OccurrenceRole::PathSegment),
            "path-segment rows must not be emitted without a namespace"
        );
        assert!(!result.completeness.covers(OccurrenceRole::PathSegment));
        assert!(
            result.completeness.covers(OccurrenceRole::Binder),
            "an unknown namespace for one role does not taint the others"
        );
        match &result.completeness {
            OccurrenceCompleteness::Incomplete { reasons, .. } => assert!(
                reasons.contains(&OccurrenceIncompleteReason::NamespaceUnknown(
                    OccurrenceRole::PathSegment
                )),
                "reasons: {reasons:?}"
            ),
            other => panic!("expected incomplete path-segment coverage, got {other:?}"),
        }
    }

    #[test]
    fn an_adapter_without_occurrence_roles_reports_incomplete_not_empty_complete() {
        let source = "class Widget { def render(label: String): String = label }\n";
        let fixture = Fixture::new(Language::Scala, "src/app.scala", source);
        let result = fixture.result();

        assert!(result.rows.is_empty());
        match &result.completeness {
            OccurrenceCompleteness::Incomplete {
                unsupported_roles, ..
            } => {
                assert_eq!(unsupported_roles.len(), ALL_OCCURRENCE_ROLES.len());
                for role in ALL_OCCURRENCE_ROLES {
                    assert!(!result.completeness.covers(*role), "{role} claimed covered");
                }
            }
            OccurrenceCompleteness::Complete => {
                panic!("an all-unsupported adapter must never report Complete")
            }
        }
    }

    #[test]
    fn cancellation_propagates_out_of_the_producer() {
        let source = "class Widget {\n    int render(String label) { return label.length(); }\n}\n";
        let fixture = Fixture::new(Language::Java, "app/Widget.java", source);
        let cancellation = CancellationToken::new();
        cancellation.cancel();

        let outcome =
            occurrences_for_file(fixture.workspace.analyzer(), &fixture.file, &cancellation);
        assert!(
            matches!(outcome, Err(OccurrencesCancelled)),
            "a cancelled request must not yield rows"
        );
    }

    fn trace_of<'rows>(
        rows: &'rows [OccurrenceRow],
        start_byte: usize,
        label: &str,
    ) -> &'rows ResolutionTraceResult {
        expect_row(rows, start_byte, label)
            .candidates
            .as_ref()
            .unwrap_or_else(|| panic!("no trace attached to {label}"))
    }

    fn rejections(trace: &ResolutionTraceResult, reason: RejectionReason) -> Vec<&TraceCandidate> {
        trace
            .rejected()
            .filter(|row| row.outcome.rejection() == Some(reason))
            .collect()
    }

    /// A caller that does not ask for candidates gets none, and the rows it
    /// does get are unchanged. This is the "existing consumers pay nothing"
    /// contract stated as behavior rather than as an intention.
    #[test]
    fn candidates_are_absent_unless_the_caller_asks_for_them() {
        let source = "fn render(label: &str) -> usize {\n    label.len()\n}\n";
        let fixture = Fixture::new(Language::Rust, "src/app.rs", source);

        let plain = fixture.result();
        assert!(
            plain.rows.iter().all(|row| row.candidates.is_none()),
            "an unasked derivation must attach no trace"
        );

        let traced = fixture.traced_result();
        assert!(
            traced
                .rows
                .iter()
                .filter(|row| row.class == OccurrenceClass::Reference)
                .all(|row| row.candidates.is_some()),
            "every reference row of a traced derivation carries its trace"
        );
        assert!(
            traced
                .rows
                .iter()
                .filter(|row| row.class != OccurrenceClass::Reference)
                .all(|row| row.candidates.is_none()),
            "only reference-class rows have candidates to report"
        );
        assert_eq!(
            plain.rows.len(),
            traced.rows.len(),
            "asking for candidates must not change which rows exist"
        );
    }

    /// The mined `61c223586` shape: an inner binding shadows an outer one of
    /// the same name. The read between them selects the inner binder at the
    /// lexical tier, and the outer binder is reported as a rejected candidate
    /// with the reason that discarded it.
    #[test]
    fn a_shadowed_rust_binding_is_reported_as_rejected_beside_the_selected_local() {
        let source = concat!(
            "fn render() -> usize {\n",
            "    let label = 1;\n",
            "    {\n",
            "        let label = 2;\n",
            "        return label;\n",
            "    }\n",
            "}\n",
        );
        let fixture = Fixture::new(Language::Rust, "src/app.rs", source);
        let result = fixture.traced_result();
        let trace = trace_of(&result.rows, fixture.at("label;"), "shadowed read");

        assert_eq!(
            trace.completeness,
            TraceCompleteness::Full,
            "Rust declares the rejection axis, so its trace claims Full"
        );
        assert!(
            trace.selects_at(PrecedenceTier::LexicalBinding),
            "the inner binder is the selection: {:?}",
            trace.candidates
        );
        let shadowed = rejections(trace, RejectionReason::ShadowedByNearer);
        assert_eq!(
            shadowed.len(),
            1,
            "exactly the outer binder loses: {:?}",
            trace.candidates
        );
        assert_eq!(shadowed[0].tier, Some(PrecedenceTier::LexicalBinding));
        match &shadowed[0].candidate {
            TraceCandidateRef::Binding { name, .. } => assert_eq!(name, "label"),
            other => panic!("a shadowed binder is an environment binding row, got {other:?}"),
        }
    }

    /// Java resolves a simple type name against single-type imports before
    /// on-demand ones, so an explicit import selects at its tier and the
    /// wildcard routes it beat are recorded as rejected peers.
    #[test]
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

    /// Python and JS/TS reach the shared outcome constructors but no tier of
    /// their resolvers reports what it discarded, so their traces say so
    /// instead of letting an absent rejection row read as "nothing lost".
    #[test]
    fn a_language_without_tier_tracing_reports_selection_only() {
        let python = Fixture::new(
            Language::Python,
            "src/app.py",
            "def render(label):\n    return label\n",
        );
        let python_result = python.traced_result();
        assert_eq!(
            trace_of(&python_result.rows, python.at("label\n"), "python read").completeness,
            TraceCompleteness::SelectionOnly
        );

        let js = Fixture::new(
            Language::JavaScript,
            "src/app.js",
            "function render(label) {\n    return label;\n}\n",
        );
        let js_result = js.traced_result();
        assert_eq!(
            trace_of(&js_result.rows, js.at("label;"), "javascript read").completeness,
            TraceCompleteness::SelectionOnly
        );
    }

    /// An adapter that has not learned the candidate axes must surface that
    /// through the capability spine. An empty trace from an uninstrumented
    /// language would read exactly like "the resolver considered nothing".
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
            !result.completeness.is_complete(),
            "an adapter with no occurrence roles can never report Complete"
        );
        assert!(
            result.rows.is_empty(),
            "no rows means no traces, which is the honest answer here"
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
