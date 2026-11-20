//! `field_writes_of` and `field_reads_of`: the modeled stores to and loads of
//! one field declaration, with the site and the stored value of each.
//!
//! Both steps classify stores and loads from one `PropertyReachingResult` per
//! candidate procedure, obtained through the single acquisition path that
//! flow-state derivation also uses. The candidate procedures are the
//! procedures enclosing every usage of the field, proven or not, whatever its
//! reference facets: a struct-literal initializer carries no write facet.
//!
//! A record is matched to the seed field through the usage scan, which is the
//! authority on which names in which expressions refer to the seed. A Rust
//! member locator names only the field's spelling, so spelling alone never
//! selects a record. A record that spelling cannot rule out and that no proven
//! usage locates makes the answer incomplete instead of being guessed at.

use super::super::occurrence_rows::{
    OccurrenceDerivationOptions, OccurrenceRow, OccurrenceTarget,
    occurrences_for_file_with_options_and_roles, resolve_occurrence_targets_for_rows,
};
use super::*;
use crate::analyzer::semantic::{
    CandidateCoverage, CapabilitySupport, LifecycleIncompleteReason, MemoryAccessKind,
    MemoryLocationKind, PointerOriginKind, ProcedureHandle, ProcedureSemantics, ProgramPointHandle,
    ProgramPointId, PropertyReachingIncompleteReason, PropertyReachingResult, SemanticCapability,
    SemanticEffect, SemanticGapImpact, SemanticGapKind, SemanticIncompleteReason, SemanticLocator,
    SemanticPlace, SemanticValueKind, SourceMapping, SourceMappingId, ValueId,
};
use brokk_bifrost_analysis::analyzer::structural::facts::FileFacts;
use brokk_bifrost_analysis::analyzer::structural::provider::StructuralSyntaxLimitedOutcome;
use brokk_bifrost_core::analyzer::language_knowledge::LanguageKnowledge;
use brokk_bifrost_core::analyzer::structural::kinds::{NormalizedKind, Role};
use brokk_bifrost_flow::flow_state::FlowStateIncompleteReason;
use brokk_bifrost_tools::program_point_selection::{node_site_value, source_site};
use brokk_bifrost_tools::site_context::{
    KnownValue, SiteAdmission, SiteAdmissionRefusal, SiteContext, SiteRole, SiteValue,
    UnknownValueCause, view,
};
use std::cell::OnceCell;
use std::collections::{BTreeMap, HashMap, HashSet};

const WRITE_ID_DOMAIN: &[u8] = b"bifrost.field_write.v1";
const READ_ID_DOMAIN: &[u8] = b"bifrost.field_read.v1";

/// A field write or read ready to publish. The row is complete at expansion
/// time; the rest locates it for evidence and provenance.
#[derive(Debug, Clone)]
pub(super) struct FieldAccessValue<R> {
    pub(super) row: R,
    pub(super) file: ProjectFile,
    pub(super) range: Range,
}

impl FieldAccessValue<CodeQueryFieldWrite> {
    pub(super) fn detailed_key(&self) -> DetailedCodeQueryKey {
        DetailedCodeQueryKey::FieldWrite {
            id: self.row.id.clone(),
            procedure_id: self.row.procedure_id.clone(),
            program_point_id: self.row.program_point_id.clone(),
        }
    }
}

impl FieldAccessValue<CodeQueryFieldRead> {
    pub(super) fn detailed_key(&self) -> DetailedCodeQueryKey {
        DetailedCodeQueryKey::FieldRead {
            id: self.row.id.clone(),
            procedure_id: self.row.procedure_id.clone(),
            program_point_id: self.row.program_point_id.clone(),
        }
    }
}

/// A byte span of one file.
type Bytes = (usize, usize);

fn contains(outer: Bytes, inner: Bytes) -> bool {
    outer.0 <= inner.0 && inner.1 <= outer.1
}

fn strictly_contains(outer: Bytes, inner: Bytes) -> bool {
    contains(outer, inner) && outer != inner
}

/// The seed field and the usage sites of it, per file.
struct Seed<'a> {
    declaration: &'a DeclarationValue,
    /// The field's spelling, as a member locator names it.
    name: &'a str,
    field_id: String,
}

struct FileScan {
    facts: Arc<FileFacts>,
    syntax: Option<Arc<brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree>>,
    knowledge: Option<&'static dyn LanguageKnowledge>,
    proven: Vec<Bytes>,
    unproven: Vec<Bytes>,
    /// The first structural node of each exact span, for a source mapping
    /// that names no node of its own.
    nodes_by_span: HashMap<Bytes, u32>,
    /// The identity rows of the file, derived when the first member token
    /// needs its target resolved.
    identity_rows: OnceCell<Vec<OccurrenceRow>>,
}

struct CandidateProcedure {
    /// The enclosing callable's name.
    label: String,
    file: ProjectFile,
    handle: ProcedureHandle,
    result: PropertyReachingResult,
}

/// The sort key of a published access: file, site, event index.
type AccessKey = (String, Bytes, u32);

/// How a record's member locator relates to the seed field.
#[derive(Clone, Copy, PartialEq, Eq)]
enum MemberRelation {
    /// The locator names the seed: it carries the seed's own declaration
    /// anchor, its anchor lies in a usage of the seed, or it spells the seed's
    /// name where it can name nothing more.
    Names,
    /// The locator carries an anchor inside the seed's declaration span, but
    /// for another file. Only a usage can say whether that is the seed.
    NeedsUsage,
    /// The locator names some other member.
    Other,
}

fn member_relation(member: &SemanticLocator, seed: &Seed<'_>, scan: &FileScan) -> MemberRelation {
    if member.is_artifact_independent_field() {
        // A Rust member locator carries only the field's spelling, as a
        // structured segment key.
        let key = member
            .declaration()
            .segments()
            .last()
            .and_then(|segment| segment.name())
            .and_then(|name| name.strip_prefix("rust-field:"));
        let same = key.is_some_and(|key| {
            key.strip_prefix("named:")
                .or_else(|| key.strip_prefix("tuple:"))
                .is_some_and(|spelling| spelling == seed.name)
        });
        return if same {
            MemberRelation::Names
        } else {
            MemberRelation::Other
        };
    }
    let span = member.anchor().span();
    let anchor = (span.start_byte() as usize, span.end_byte() as usize);
    let seed_range = (
        seed.declaration.range.start_byte,
        seed.declaration.range.end_byte,
    );
    if contains(seed_range, anchor) {
        let seed_path = crate::path_utils::workspace_relative_slash_path(
            seed.declaration.unit.source().rel_path(),
        );
        return if member.path().as_str() == seed_path {
            MemberRelation::Names
        } else {
            MemberRelation::NeedsUsage
        };
    }
    if scan
        .proven
        .iter()
        .chain(&scan.unproven)
        .any(|usage| contains(*usage, anchor))
    {
        return MemberRelation::Names;
    }
    MemberRelation::Other
}

fn mapping_bytes(semantics: &ProcedureSemantics, id: SourceMappingId) -> Option<Bytes> {
    let span = semantics.source_mapping(id)?.locator.anchor().span();
    Some((span.start_byte() as usize, span.end_byte() as usize))
}

/// The structural node a source mapping names: its exact structural identity,
/// or else a node of exactly its span.
fn mapped_node(scan: &FileScan, mapping: &SourceMapping, bytes: Bytes) -> Option<u32> {
    if let Some(identity) = mapping.ast_identity
        && identity.content() == scan.facts.source_identity()
    {
        return Some(identity.node_id());
    }
    scan.nodes_by_span.get(&bytes).copied()
}

/// What a store or load looks like at its source.
struct AccessSpans {
    /// The span the IR attributes the event to.
    event: Bytes,
    event_kind: Option<NormalizedKind>,
    event_node: Option<u32>,
    /// The span of the stored or loaded value, when it is a node of its own.
    value: Option<Bytes>,
    value_node: Option<u32>,
}

fn access_spans(
    semantics: &ProcedureSemantics,
    scan: &FileScan,
    event: SourceMappingId,
    value: ValueId,
) -> Option<AccessSpans> {
    let event_mapping = semantics.source_mapping(event)?;
    let event_bytes = mapping_bytes(semantics, event)?;
    let facts = &scan.facts;
    let event_node = mapped_node(scan, event_mapping, event_bytes);
    let value_mapping = semantics
        .value(value)
        .and_then(|value| semantics.source_mapping(value.source));
    let value_bytes = value_mapping.map(|mapping| {
        let span = mapping.locator.anchor().span();
        (span.start_byte() as usize, span.end_byte() as usize)
    });
    let (value, value_node) = match (value_mapping, value_bytes) {
        (Some(mapping), Some(bytes)) if strictly_contains(event_bytes, bytes) => {
            (Some(bytes), mapped_node(scan, mapping, bytes))
        }
        _ => (None, None),
    };
    Some(AccessSpans {
        event: event_bytes,
        event_kind: event_node.map(|node| facts.node(node).kind),
        event_node,
        value,
        value_node,
    })
}

/// The member token of an assignment LHS or field-access node. Reading `Role::Field`
/// ensures an expression inside the receiver (`b_slot(b, a.x).x`) never locates
/// the outer access as an access to `a.x`.
fn member_token_bytes(facts: &FileFacts, node_id: u32) -> Option<Bytes> {
    match facts.node(node_id).kind {
        NormalizedKind::FieldAccess => facts
            .role_targets(node_id, Role::Field)
            .next()
            .map(|target| (target.span.start_byte, target.span.end_byte)),
        NormalizedKind::Identifier => {
            let span = facts.node(node_id).span();
            Some((span.start_byte, span.end_byte))
        }
        _ => None,
    }
}

/// The aggregate initializer (`Foo { f: expr }` or shorthand `Foo { f }`)
/// around a value node, read from the parsed syntax tree through the
/// language's initializer hook: the initializer's span and its key token.
/// Only that initializer's own key is returned, never an earlier usage
/// elsewhere in the aggregate (`B { other: a.x, x: 2 }`).
fn enclosing_initializer(scan: &FileScan, event: Bytes, value: Bytes) -> Option<(Bytes, Bytes)> {
    let knowledge = scan.knowledge?;
    let tree = scan.syntax.as_ref()?.tree();
    let mut current = Some(
        tree.root_node()
            .descendant_for_byte_range(value.0, value.1)?,
    );
    while let Some(node) = current {
        let node_bytes = (node.start_byte(), node.end_byte());
        if !strictly_contains(event, node_bytes) {
            break;
        }
        if let Some((key, initial)) = knowledge.aggregate_member_initializer(node)
            && contains((initial.start_byte(), initial.end_byte()), value)
        {
            return Some((node_bytes, (key.start_byte(), key.end_byte())));
        }
        current = node.parent();
    }
    None
}

/// The member token of the operand of an increment or decrement event
/// (`this.x++`, `--x`), read from the parsed syntax tree through the
/// language's update hook. The store such an expression lowers to is mapped
/// to the whole expression, which has no structural kind of its own.
fn update_operand_member(scan: &FileScan, event: Bytes) -> Option<Bytes> {
    let knowledge = scan.knowledge?;
    let tree = scan.syntax.as_ref()?.tree();
    let node = tree
        .root_node()
        .descendant_for_byte_range(event.0, event.1)?;
    if (node.start_byte(), node.end_byte()) != event {
        return None;
    }
    let operand = knowledge.update_operand(node)?;
    let operand = *scan
        .nodes_by_span
        .get(&(operand.start_byte(), operand.end_byte()))?;
    member_token_bytes(&scan.facts, operand)
}

fn locate_initializer_in_tree(
    scan: &FileScan,
    event: Bytes,
    value: Bytes,
) -> Option<(Bytes, UsageProof)> {
    let (initializer, key) = enclosing_initializer(scan, event, value)?;
    usage_within(scan, key).map(|proof| (initializer, proof))
}

/// How the usage scan covers a member token: a proven usage inside it first,
/// else an unproven one.
fn usage_within(scan: &FileScan, token: Bytes) -> Option<UsageProof> {
    if scan.proven.iter().any(|usage| contains(token, *usage)) {
        Some(UsageProof::Proven)
    } else if scan.unproven.iter().any(|usage| contains(token, *usage)) {
        Some(UsageProof::Unproven)
    } else {
        None
    }
}

/// The span of the whole access that a usage of the seed locates, and how
/// well that usage is proven.
///
/// An assignment is located by the member token of its left side, so neither
/// the right side nor a field read inside a receiver expression locates a
/// write. A field access is located by its `Role::Field` token, and an
/// increment or decrement by the member token of its operand. A
/// struct-literal initializer is located from the syntax tree by the key node
/// paired with its value node (or the shorthand identifier itself), so the
/// access is that initializer and never another field of the literal.
fn located_access(scan: &FileScan, spans: &AccessSpans) -> Option<(Bytes, UsageProof)> {
    let facts = &scan.facts;
    if spans.event_kind == Some(NormalizedKind::Assignment) {
        let left = facts.role_targets(spans.event_node?, Role::Left).next()?;
        let member = member_token_bytes(facts, left.node?)?;
        return usage_within(scan, member).map(|proof| (spans.event, proof));
    }
    if spans.event_kind == Some(NormalizedKind::FieldAccess) {
        let member = member_token_bytes(facts, spans.event_node?)?;
        return usage_within(scan, member).map(|proof| (spans.event, proof));
    }
    if spans.event_kind == Some(NormalizedKind::Identifier) {
        return usage_within(scan, spans.event).map(|proof| (spans.event, proof));
    }
    if let Some(member) = update_operand_member(scan, spans.event) {
        return usage_within(scan, member).map(|proof| (spans.event, proof));
    }
    if let Some(value) = spans.value {
        return locate_initializer_in_tree(scan, spans.event, value);
    }
    None
}

/// The member token an explicit access names at its own site: the member of
/// an assignment's left side or a field access, the identifier itself, or the
/// key of an aggregate initializer around the stored value.
fn member_access_token(scan: &FileScan, spans: &AccessSpans) -> Option<Bytes> {
    let facts = &scan.facts;
    match spans.event_kind {
        Some(NormalizedKind::Assignment) => {
            let left = facts.role_targets(spans.event_node?, Role::Left).next()?;
            member_token_bytes(facts, left.node?)
        }
        Some(NormalizedKind::FieldAccess) => member_token_bytes(facts, spans.event_node?),
        Some(NormalizedKind::Identifier) => Some(spans.event),
        _ => update_operand_member(scan, spans.event)
            .or_else(|| enclosing_initializer(scan, spans.event, spans.value?).map(|(_, key)| key)),
    }
}

/// The field stores that only copy an aggregate: a store whose value is the
/// load of the same member from the result of an allocation of this
/// procedure. A by-value return, a closure result or a `let` copies such an
/// aggregate into a result temporary with no member token of its own. The
/// copied contents come from the stores that initialize or assign the
/// allocation, and each of those is a record of its own.
///
/// The set also holds the load half of each such copy.
///
/// A copy from a parameter, a call result or any other value is not in the
/// set: where its contents come from is unknown here.
fn field_transfer_stores(semantics: &ProcedureSemantics) -> HashSet<(ProgramPointId, u32)> {
    let field_of = |location| match &semantics.memory_location(location)?.kind {
        MemoryLocationKind::Field { base, member } => Some((*base, member)),
        _ => None,
    };
    let allocated: HashSet<ValueId> = semantics
        .allocations()
        .iter()
        .map(|allocation| allocation.result)
        .collect();
    let mut loads = HashMap::new();
    let mut transfers = HashSet::new();
    for point in semantics.points() {
        for (index, event) in point.events.iter().enumerate() {
            match &event.effect {
                SemanticEffect::MemoryLoad {
                    location, result, ..
                } => {
                    if let Some(field) = field_of(*location) {
                        let index = u32::try_from(index).expect("event index fits u32");
                        loads.insert(*result, (field, (point.id, index)));
                    }
                }
                SemanticEffect::MemoryStore {
                    location, value, ..
                } => {
                    let copied = field_of(*location).zip(loads.get(value));
                    if let Some(((_, member), ((source, loaded), load_event))) = copied
                        && allocated.contains(source)
                        && *loaded == member
                    {
                        let index = u32::try_from(index).expect("event index fits u32");
                        transfers.insert((point.id, index));
                        // The load half of the copy is no access of its own.
                        transfers.insert(*load_event);
                    }
                }
                _ => {}
            }
        }
    }
    transfers
}

/// Whether the member token is proven to name a declaration other than the
/// seed. A token that resolves to nothing, to the seed, or to several
/// declarations is not proven to name another one.
fn token_resolves_elsewhere(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    scan: &FileScan,
    seed: &Seed<'_>,
    token: Bytes,
    cancellation: Option<&CancellationToken>,
) -> bool {
    let uncancelled = CancellationToken::default();
    let cancellation = cancellation.unwrap_or(&uncancelled);
    let identity_rows = scan.identity_rows.get_or_init(|| {
        occurrences_for_file_with_options_and_roles(
            analyzer,
            file,
            OccurrenceDerivationOptions::IDENTITY_ONLY,
            None,
            cancellation,
        )
        .map(|result| result.rows)
        .unwrap_or_default()
    });
    let mut rows: Vec<OccurrenceRow> = identity_rows
        .iter()
        .filter(|row| (row.range.start_byte, row.range.end_byte) == token)
        .cloned()
        .collect();
    if rows.is_empty()
        || resolve_occurrence_targets_for_rows(analyzer, file, &mut rows, cancellation).is_err()
    {
        return false;
    }
    rows.iter().all(|row| match &row.target {
        OccurrenceTarget::Resolved(units) => {
            !units.is_empty() && !units.contains(&seed.declaration.unit)
        }
        _ => false,
    })
}

fn site_context(
    file: &ProjectFile,
    facts: &FileFacts,
    bytes: Bytes,
    role: SiteRole,
    value: SiteValue,
) -> SiteContext {
    SiteContext {
        site: source_site(file, facts, bytes.0..bytes.1),
        role,
        value,
    }
}

fn query_range(facts: &FileFacts, bytes: Bytes) -> CodeQueryRange {
    let (start_line, start_column) = facts.line_column_of_byte(bytes.0);
    let (end_line, end_column) = facts.line_column_of_byte(bytes.1);
    CodeQueryRange {
        start_line,
        start_column,
        end_line,
        end_column,
    }
}

fn access_range(facts: &FileFacts, bytes: Bytes) -> Range {
    Range {
        start_byte: bytes.0,
        end_byte: bytes.1,
        start_line: facts.line_of_byte(bytes.0),
        end_line: facts.line_of_byte(bytes.1),
    }
}

fn access_id(
    domain: &[u8],
    file: &ProjectFile,
    procedure_id: &str,
    point_id: &str,
    event_index: u32,
    field_id: &str,
) -> String {
    let mut digest = LengthDelimitedDigest::new(domain);
    digest.push(rel_path_string(file).as_bytes());
    digest.push(procedure_id.as_bytes());
    digest.push(point_id.as_bytes());
    digest.push(&u64::from(event_index).to_le_bytes());
    digest.push(field_id.as_bytes());
    digest.finish().to_string()
}

fn incomplete(semantic: &mut SemanticQueryContext<'_>, file: &ProjectFile, message: String) {
    semantic.push_diagnostic(
        CodeQueryDiagnosticCode::SemanticAnalysisPartial,
        Incompleteness::Content,
        CodeQueryDiagnosticImpact::Incomplete,
        file,
        &message,
    );
}

fn incomplete_items<T: std::fmt::Debug>(
    semantic: &mut SemanticQueryContext<'_>,
    file: &ProjectFile,
    summary: String,
    items: &[T],
) {
    let message = brokk_bifrost_core::bounded_output::bounded_diagnostic_items(
        format_args!("{summary}: {items:?}"),
        format_args!("{summary}"),
        items.iter(),
    );
    incomplete(semantic, file, message);
}

/// A seed that is not a field has no field accesses.
pub(super) fn report_not_a_field(
    semantic: &mut SemanticQueryContext<'_>,
    step: &str,
    declaration: &DeclarationValue,
) {
    semantic.push_diagnostic(
        CodeQueryDiagnosticCode::NoEnclosingProcedure,
        Incompleteness::Content,
        CodeQueryDiagnosticImpact::Advisory,
        declaration.unit.source(),
        &format!(
            "{step} requires a field declaration; {} is not a field",
            declaration.unit.fq_name()
        ),
    );
}

/// A derive, attribute macro or annotation on the seed's owner type or on the
/// seed itself can generate reads and writes of the field that no source
/// occurrence shows (`#[derive(Default)]`, Lombok `@Data`). Without macro
/// output models they make the answer incomplete.
fn report_unmodeled_field_access_macros(
    step: &str,
    analyzer: &dyn IAnalyzer,
    semantic: &mut SemanticQueryContext<'_>,
    seed: &Seed<'_>,
    cancellation: Option<&CancellationToken>,
) {
    let unit = &seed.declaration.unit;
    let file = unit.source();
    let language = crate::analyzer::common::language_for_file(file);
    let Some(knowledge) = crate::analyzer::languages::language_knowledge(language) else {
        return;
    };
    let Some(provider) = analyzer
        .structural_fact_providers()
        .into_iter()
        .find(|provider| provider.structural_language() == language)
    else {
        return;
    };
    report_field_access_macros_from_provider(
        step,
        analyzer,
        semantic,
        seed.declaration,
        cancellation,
        knowledge,
        provider,
    );
}

/// Inspect the seed through its provider even when usage discovery found no
/// candidate files. Keeping acquisition here also lets provider-boundary tests
/// exercise typed stops without changing the analyzer's real facts.
pub(super) fn report_field_access_macros_from_provider(
    step: &str,
    analyzer: &dyn IAnalyzer,
    semantic: &mut SemanticQueryContext<'_>,
    declaration: &DeclarationValue,
    cancellation: Option<&CancellationToken>,
    knowledge: &dyn LanguageKnowledge,
    provider: &dyn brokk_bifrost_analysis::analyzer::structural::provider::StructuralFactProvider,
) {
    let unit = &declaration.unit;
    let file = unit.source();
    let Some(facts) = provider.structural_facts(file) else {
        return;
    };
    let syntax = match provider.structural_syntax_limited(file, facts.source().len(), cancellation)
    {
        StructuralSyntaxLimitedOutcome::Available(syntax) => syntax,
        StructuralSyntaxLimitedOutcome::Exceeded { .. } => {
            semantic.push_diagnostic(
                CodeQueryDiagnosticCode::SemanticBudgetExhausted,
                Incompleteness::Operational(brokk_bifrost_rql::DiagnosticExecutionCause::Budget),
                CodeQueryDiagnosticImpact::Incomplete,
                file,
                &format!(
                    "{step} exceeded syntax preparation budget inspecting macros for {} in {}",
                    unit.fq_name(),
                    rel_path_string(file)
                ),
            );
            return;
        }
        StructuralSyntaxLimitedOutcome::Cancelled => {
            semantic.push_diagnostic(
                CodeQueryDiagnosticCode::Cancelled,
                Incompleteness::Operational(brokk_bifrost_rql::DiagnosticExecutionCause::Cancelled),
                CodeQueryDiagnosticImpact::Incomplete,
                file,
                &format!(
                    "{step} cancelled syntax preparation inspecting macros for {} in {}",
                    unit.fq_name(),
                    rel_path_string(file)
                ),
            );
            return;
        }
        StructuralSyntaxLimitedOutcome::Unavailable => {
            incomplete(
                semantic,
                file,
                format!(
                    "{step} has no prepared syntax to inspect macros for {} in {}",
                    unit.fq_name(),
                    rel_path_string(file)
                ),
            );
            return;
        }
    };
    if syntax.prepared().source() != facts.source() {
        semantic.push_diagnostic(
            CodeQueryDiagnosticCode::SemanticAnalysisPartial,
            Incompleteness::Operational(brokk_bifrost_rql::DiagnosticExecutionCause::Snapshot),
            CodeQueryDiagnosticImpact::Incomplete,
            file,
            &format!(
                "{step} cannot inspect macros for {} in {} because prepared syntax and structural facts have different source snapshots",
                unit.fq_name(),
                rel_path_string(file)
            ),
        );
        return;
    }
    let source = facts.source();
    let prepared = syntax.clone_prepared();
    let root = prepared.tree().root_node();
    let range = declaration.range;
    let Some(field) = root.descendant_for_byte_range(range.start_byte, range.end_byte) else {
        return;
    };
    // The outermost ancestor of the field inside its parent declaration, other
    // than the root, is the owner type's declaration node.
    let owner = analyzer.parent_of(unit).and_then(|parent| {
        let parent_ranges = analyzer.ranges_of(&parent);
        let parent_range = parent_ranges.iter().find(|candidate| {
            contains(
                (candidate.start_byte, candidate.end_byte),
                (range.start_byte, range.end_byte),
            )
        })?;
        let mut owner = None;
        let mut node = field;
        while let Some(ancestor) = node.parent() {
            if ancestor.parent().is_none()
                || !contains(
                    (parent_range.start_byte, parent_range.end_byte),
                    (ancestor.start_byte(), ancestor.end_byte()),
                )
            {
                break;
            }
            owner = Some(ancestor);
            node = ancestor;
        }
        owner
    });
    let mut macros = knowledge.unmodeled_field_access_macros(root, owner, Some(field), source);
    if macros.is_empty() {
        return;
    }
    macros.sort_unstable();
    macros.dedup();
    incomplete_items(
        semantic,
        file,
        format!(
            "{step} cannot see reads or writes of {} that code generated by unexpanded macros or annotations performs",
            unit.fq_name()
        ),
        &macros,
    );
}

/// Procedure-level reasons the answer may miss an access: gaps that impact
/// `impacts`, unsupported pointer or macro facts, an address taken of the
/// field, and the property relation's own incompleteness. Unresolved
/// dereference accesses are reported by the caller, which knows whether it
/// asks for stores or loads.
fn report_procedure_incompleteness(
    semantic: &mut SemanticQueryContext<'_>,
    step: &str,
    seed: &Seed<'_>,
    scan: &FileScan,
    candidate: &CandidateProcedure,
    impacts: &[SemanticGapImpact],
) {
    let semantics = candidate.handle.semantics();
    let procedure_id = candidate.label.as_str();
    let file = &candidate.file;

    let mut gaps = Vec::new();
    let mut exceeded = false;
    for gap in semantics.gaps() {
        // Implicit drop glue is not a writer of the seed, and an omitted
        // exceptional route that never rejoins the body performs none:
        // flow-state closes its relation axes over the same gaps.
        if gap.is_implicit_drop_omission()
            || brokk_bifrost_flow::flow_state::gap_has_exit_only_control(gap)
        {
            continue;
        }
        if impacts.iter().any(|impact| gap.impacts.contains(*impact)) {
            exceeded |= gap.kind == SemanticGapKind::ExceededBudget;
            gaps.push(format!(
                "{} {} at point {}: {}",
                gap.capability.label(),
                gap.kind.label(),
                gap.point.index(),
                gap.detail
            ));
        }
    }
    if !gaps.is_empty() {
        if exceeded {
            semantic.push_diagnostic(
                CodeQueryDiagnosticCode::SemanticBudgetExhausted,
                Incompleteness::Operational(brokk_bifrost_rql::DiagnosticExecutionCause::Budget),
                CodeQueryDiagnosticImpact::Incomplete,
                file,
                &format!("{step} found a budget-limited gap in procedure `{procedure_id}`"),
            );
        }
        incomplete_items(
            semantic,
            file,
            format!(
                "{step} found semantic gaps in procedure `{procedure_id}` that could hide an access"
            ),
            &gaps,
        );
    }

    let facts: Vec<String> = semantics
        .incomplete_facts()
        .iter()
        .filter(|fact| {
            matches!(
                fact.reason,
                SemanticIncompleteReason::Pointer(_)
                    | SemanticIncompleteReason::Lifecycle(
                        LifecycleIncompleteReason::UnsupportedMacroExpansion
                    )
            )
        })
        .map(|fact| format!("point {}: {:?}", fact.point.index(), fact.reason))
        .collect();
    if !facts.is_empty() {
        incomplete_items(
            semantic,
            file,
            format!(
                "{step} found unsupported pointer or macro semantics in procedure `{procedure_id}`"
            ),
            &facts,
        );
    }

    let mut borrowed = Vec::new();
    for origin in semantics.pointer_origins() {
        let PointerOriginKind::StackPlace {
            place: SemanticPlace::MemoryLocation(location),
        } = &origin.kind
        else {
            continue;
        };
        let Some(MemoryLocationKind::Field { member, .. }) = semantics
            .memory_location(*location)
            .map(|place| &place.kind)
        else {
            continue;
        };
        if member_relation(member, seed, scan) != MemberRelation::Other {
            borrowed.push(format!("point {}", origin.point.index()));
        }
    }
    if !borrowed.is_empty() {
        incomplete_items(
            semantic,
            file,
            format!(
                "{step} found the address of {} taken in procedure `{procedure_id}`; accesses through it are not modeled as field accesses",
                seed.declaration.unit.fq_name()
            ),
            &borrowed,
        );
    }

    // `CandidateCoverage::Open` states that aliases outside the procedure may
    // reach a store; it never drops a store or load of this procedure, and a
    // store elsewhere is found through the usage scan. It therefore does not
    // make the inventory incomplete, unlike a truncated or failed relation.
    let result = &candidate.result;
    let (budget, other): (Vec<_>, Vec<_>) = result
        .incomplete_reasons()
        .iter()
        .filter(|reason| {
            !matches!(
                reason,
                PropertyReachingIncompleteReason::CandidateCoverage(CandidateCoverage::Open)
            )
        })
        .partition(|reason| property_reason_is_budget(reason));
    if !budget.is_empty() {
        semantic.push_diagnostic(
            CodeQueryDiagnosticCode::SemanticBudgetExhausted,
            Incompleteness::Operational(brokk_bifrost_rql::DiagnosticExecutionCause::Budget),
            CodeQueryDiagnosticImpact::Incomplete,
            file,
            &brokk_bifrost_core::bounded_output::bounded_diagnostic_items(
                format_args!(
                    "{step} exhausted a budget deriving property relations of procedure `{procedure_id}`: {budget:?}"
                ),
                format_args!(
                    "{step} exhausted a budget deriving property relations of procedure `{procedure_id}`"
                ),
                budget.iter(),
            ),
        );
    }
    if !other.is_empty() {
        incomplete_items(
            semantic,
            file,
            format!("{step} found incomplete property relations in procedure `{procedure_id}`"),
            &other,
        );
    }
}

fn property_reason_is_budget(reason: &PropertyReachingIncompleteReason) -> bool {
    use crate::analyzer::semantic::cfg_algorithms::CfgAlgorithmError;
    let budget = |error: &CfgAlgorithmError<ProgramPointId>| {
        matches!(
            error,
            CfgAlgorithmError::ExceededBudget(_) | CfgAlgorithmError::Cancelled { .. }
        )
    };
    match reason {
        PropertyReachingIncompleteReason::InputRelationBudgetExceeded { .. }
        | PropertyReachingIncompleteReason::ReachingPairBudgetExceeded { .. }
        | PropertyReachingIncompleteReason::Cancelled => true,
        PropertyReachingIncompleteReason::CandidateCoverage(coverage) => {
            *coverage == CandidateCoverage::Truncated
        }
        PropertyReachingIncompleteReason::ReachingDefinitions(error)
        | PropertyReachingIncompleteReason::Reachability(error)
        | PropertyReachingIncompleteReason::Dominators(error)
        | PropertyReachingIncompleteReason::ReachingPairs(error) => budget(error),
        _ => false,
    }
}

/// Stores through a pointer that the property relation did not resolve to a
/// field: they are silently absent from it, so they could be writes to the
/// seed.
fn unresolved_dereference_stores(
    semantics: &ProcedureSemantics,
    result: &PropertyReachingResult,
) -> Vec<String> {
    let resolved: HashSet<(ProgramPointId, u32)> = result
        .stores()
        .iter()
        .map(|store| (store.point.id(), store.event_index))
        .collect();
    let mut unresolved = Vec::new();
    for point in semantics.points() {
        for (index, event) in point.events.iter().enumerate() {
            if matches!(
                event.effect,
                SemanticEffect::MemoryStore {
                    kind: MemoryAccessKind::Dereference,
                    ..
                }
            ) && !resolved.contains(&(point.id, index as u32))
            {
                unresolved.push(format!("point {} event {index}", point.id.index()));
            }
        }
    }
    unresolved
}

/// Loads through a pointer that the property relation did not resolve to a
/// field.
fn unresolved_dereference_loads(
    semantics: &ProcedureSemantics,
    result: &PropertyReachingResult,
) -> Vec<String> {
    let resolved: HashSet<(ProgramPointId, u32)> = result
        .reads()
        .iter()
        .map(|read| (read.point.id(), read.event_index))
        .collect();
    let mut unresolved = Vec::new();
    for point in semantics.points() {
        for (index, event) in point.events.iter().enumerate() {
            if matches!(
                event.effect,
                SemanticEffect::MemoryLoad {
                    kind: MemoryAccessKind::Dereference,
                    ..
                }
            ) && !resolved.contains(&(point.id, index as u32))
            {
                unresolved.push(format!("point {} event {index}", point.id.index()));
            }
        }
    }
    unresolved
}

fn procedure_label(
    analyzer: &dyn IAnalyzer,
    facts: &FileFacts,
    file: &ProjectFile,
    handle: &ProcedureHandle,
) -> String {
    let span = handle.semantics().locator().anchor().span();
    let bytes = (span.start_byte() as usize, span.end_byte() as usize);
    enclosing_name(analyzer, file, &access_range(facts, bytes))
}

fn enclosing_name(analyzer: &dyn IAnalyzer, file: &ProjectFile, range: &Range) -> String {
    analyzer
        .enclosing_code_unit(file, range)
        .map(|unit| unit.fq_name())
        .unwrap_or_else(|| rel_path_string(file))
}

/// The constant a stored value is: what its source node says, else what the
/// producer established for the value.
fn stored_value(
    facts: &FileFacts,
    node: Option<u32>,
    kind: Option<&SemanticValueKind>,
) -> SiteValue {
    let from_node = node.map_or(SiteValue::Unknown(UnknownValueCause::NotConstant), |node| {
        node_site_value(facts.node(node))
    });
    if !matches!(
        from_node,
        SiteValue::Unknown(UnknownValueCause::NotConstant)
    ) {
        return from_node;
    }
    match kind {
        Some(SemanticValueKind::UnsignedInteger(value)) => {
            SiteValue::Known(KnownValue::Int(value.to_string()))
        }
        Some(SemanticValueKind::SignedInteger(value)) => {
            SiteValue::Known(KnownValue::Int(value.to_string()))
        }
        Some(SemanticValueKind::Constant) => {
            SiteValue::Unknown(UnknownValueCause::ConstantPayloadUnavailable)
        }
        _ => from_node,
    }
}

/// One store or load of a candidate procedure, in the terms both kinds share.
struct AccessRecord<'r> {
    point: &'r ProgramPointHandle,
    event_index: u32,
    source: SourceMappingId,
    value: ValueId,
    member: &'r SemanticLocator,
    proof: &'static str,
    completeness: &'static str,
    proven_complete: bool,
    strong_update: bool,
}

struct LocatedAccess<'r> {
    record: AccessRecord<'r>,
    /// The whole access: an assignment, an initializer, a field read.
    site: Bytes,
    /// The stored expression, when it is a node of its own.
    value_site: Option<Bytes>,
    value: SiteValue,
}

struct Located<'r> {
    accesses: Vec<LocatedAccess<'r>>,
    /// Records the seed's spelling or declaration names, that no proven usage
    /// locates, and that name no member token at their own site.
    ambiguous: Vec<String>,
    without_proof: Vec<String>,
}

fn locate_accesses<'r>(
    analyzer: &dyn IAnalyzer,
    cancellation: Option<&CancellationToken>,
    candidate: &CandidateProcedure,
    scan: &FileScan,
    seed: &Seed<'_>,
    records: impl IntoIterator<Item = AccessRecord<'r>>,
) -> Located<'r> {
    let semantics = candidate.handle.semantics();
    let mut located = Located {
        accesses: Vec::new(),
        ambiguous: Vec::new(),
        without_proof: Vec::new(),
    };
    let mut transfers = None;
    for record in records {
        let label = format!(
            "point {} event {}",
            record.point.id().index(),
            record.event_index
        );
        let relation = member_relation(record.member, seed, scan);
        if relation == MemberRelation::Other {
            continue;
        }
        let Some(spans) = access_spans(semantics, scan, record.source, record.value) else {
            if relation == MemberRelation::Names
                && !transfers
                    .get_or_insert_with(|| field_transfer_stores(semantics))
                    .contains(&(record.point.id(), record.event_index))
            {
                located.ambiguous.push(label);
            }
            continue;
        };
        let Some((site, usage_proof)) = located_access(scan, &spans) else {
            if relation == MemberRelation::Names
                && !transfers
                    .get_or_insert_with(|| field_transfer_stores(semantics))
                    .contains(&(record.point.id(), record.event_index))
            {
                // An explicit access to another declaration's member is no
                // access to the seed. One whose token an unproven usage covers
                // is already reported as an unproven usage. Any other
                // unlocated record may be the seed's.
                let skippable = member_access_token(scan, &spans).is_some_and(|token| {
                    scan.unproven
                        .iter()
                        .any(|usage| contains(token, *usage) || contains(*usage, token))
                        || token_resolves_elsewhere(
                            analyzer,
                            &candidate.file,
                            scan,
                            seed,
                            token,
                            cancellation,
                        )
                });
                if !skippable {
                    located.ambiguous.push(label);
                }
            }
            continue;
        };
        if !record.proven_complete {
            located.without_proof.push(label);
        }
        let value = stored_value(
            &scan.facts,
            spans.value_node,
            semantics.value(record.value).map(|value| &value.kind),
        );
        // A usage the scan could not prove weakens the row's proof.
        let proof = if usage_proof == UsageProof::Unproven {
            "unproven"
        } else {
            record.proof
        };
        located.accesses.push(LocatedAccess {
            record: AccessRecord { proof, ..record },
            site,
            value_site: spans.value,
            value,
        });
    }
    located
}

/// Report what locating found that the rows alone would hide.
fn report_located(
    semantic: &mut SemanticQueryContext<'_>,
    step: &str,
    seed: &Seed<'_>,
    candidate: &CandidateProcedure,
    noun: &str,
    located: &Located<'_>,
) {
    let procedure_id = candidate.label.as_str();
    if !located.ambiguous.is_empty() {
        incomplete_items(
            semantic,
            &candidate.file,
            format!(
                "{step} found {noun} in procedure `{procedure_id}` of a field named like {} that no proven usage locates",
                seed.declaration.unit.fq_name()
            ),
            &located.ambiguous,
        );
    }
    if !located.without_proof.is_empty() {
        incomplete_items(
            semantic,
            &candidate.file,
            format!("{step} found {noun} in procedure `{procedure_id}` without complete proof"),
            &located.without_proof,
        );
    }
}

fn seed_of<'a>(declaration: &'a DeclarationValue) -> Seed<'a> {
    Seed {
        declaration,
        name: declaration.unit.identifier(),
        field_id: declaration.declaration_id(),
    }
}

/// What distinguishes the writes of a field from its reads: the step, the gap
/// impacts, the records of a property relation, and the published row.
trait AccessDirection {
    const STEP: &'static str;
    /// The plural noun of the accesses in diagnostics.
    const NOUN: &'static str;
    const IMPACTS: [SemanticGapImpact; 5];

    /// Accesses through a pointer that the relation did not resolve to a field.
    fn unresolved_dereferences(
        semantics: &ProcedureSemantics,
        result: &PropertyReachingResult,
    ) -> Vec<String>;

    fn records(result: &PropertyReachingResult) -> Vec<AccessRecord<'_>>;

    fn publish(
        context: &RowContext<'_>,
        access: LocatedAccess<'_>,
    ) -> Result<PipelineValue, SiteAdmissionRefusal>;
}

/// What a row needs from the query and the candidate procedure around it.
struct RowContext<'a> {
    analyzer: &'a dyn IAnalyzer,
    declaration: &'a DeclarationValue,
    seed: &'a Seed<'a>,
    candidate: &'a CandidateProcedure,
    facts: &'a FileFacts,
    procedure_id: &'a str,
    admission: &'a SiteAdmission<'a>,
}

struct Writes;
struct Reads;

impl AccessDirection for Writes {
    const STEP: &'static str = "field_writes_of";
    const NOUN: &'static str = "stores";
    const IMPACTS: [SemanticGapImpact; 5] = [
        SemanticGapImpact::HeapWrite,
        SemanticGapImpact::Aliasing,
        SemanticGapImpact::ValueFlow,
        SemanticGapImpact::CallEvaluation,
        SemanticGapImpact::DispatchCoverage,
    ];

    fn unresolved_dereferences(
        semantics: &ProcedureSemantics,
        result: &PropertyReachingResult,
    ) -> Vec<String> {
        unresolved_dereference_stores(semantics, result)
    }

    fn records(result: &PropertyReachingResult) -> Vec<AccessRecord<'_>> {
        result
            .stores()
            .iter()
            .map(|store| AccessRecord {
                point: &store.point,
                event_index: store.event_index,
                source: store.source,
                value: store.value.id(),
                member: &store.location.member,
                proof: store.proof.label(),
                completeness: store.completeness.label(),
                proven_complete: store.is_proven_complete(),
                strong_update: store.strong_update,
            })
            .collect()
    }

    fn publish(
        context: &RowContext<'_>,
        access: LocatedAccess<'_>,
    ) -> Result<PipelineValue, SiteAdmissionRefusal> {
        let RowContext {
            analyzer,
            declaration,
            seed,
            candidate,
            facts,
            procedure_id,
            admission,
        } = context;
        let record = &access.record;
        let member = declaration.unit.fq_name();
        // A store the stored value is no node of (a compound assignment, a
        // functional update's field transfer) has no value site and no known
        // value.
        let (stored, value_site) = match access.value_site {
            Some(bytes) => (
                access.value.clone(),
                Some(view(
                    &site_context(
                        &candidate.file,
                        facts,
                        bytes,
                        SiteRole::Value,
                        access.value.clone(),
                    ),
                    admission,
                )?),
            ),
            None => (SiteValue::Unknown(UnknownValueCause::NotConstant), None),
        };
        let write_site = site_context(
            &candidate.file,
            facts,
            access.site,
            SiteRole::FieldWrite { member },
            stored,
        );
        let point_id = semantic::program_point_wire_id(record.point);
        let range = access_range(facts, access.site);
        Ok(PipelineValue::FieldWrite(Box::new(FieldAccessValue {
            row: CodeQueryFieldWrite {
                id: access_id(
                    WRITE_ID_DOMAIN,
                    &candidate.file,
                    procedure_id,
                    &point_id,
                    record.event_index,
                    &seed.field_id,
                ),
                path: crate::path_utils::workspace_relative_slash_path(candidate.file.rel_path()),
                language: crate::analyzer::common::language_for_file(&candidate.file)
                    .config_label(),
                range: query_range(facts, access.site),
                field_id: seed.field_id.clone(),
                member_fq_name: declaration.unit.fq_name(),
                enclosing: enclosing_name(*analyzer, &candidate.file, &range),
                procedure_id: (*procedure_id).to_owned(),
                program_point_id: point_id,
                site: view(&write_site, admission)?,
                value_site,
                proof: record.proof,
                completeness: record.completeness,
                strong_update: record.strong_update,
            },
            file: candidate.file.clone(),
            range,
        })))
    }
}

impl AccessDirection for Reads {
    const STEP: &'static str = "field_reads_of";
    const NOUN: &'static str = "loads";
    const IMPACTS: [SemanticGapImpact; 5] = [
        SemanticGapImpact::HeapRead,
        SemanticGapImpact::Aliasing,
        SemanticGapImpact::ValueFlow,
        SemanticGapImpact::CallEvaluation,
        SemanticGapImpact::DispatchCoverage,
    ];

    fn unresolved_dereferences(
        semantics: &ProcedureSemantics,
        result: &PropertyReachingResult,
    ) -> Vec<String> {
        unresolved_dereference_loads(semantics, result)
    }

    fn records(result: &PropertyReachingResult) -> Vec<AccessRecord<'_>> {
        result
            .reads()
            .iter()
            .map(|read| AccessRecord {
                point: &read.point,
                event_index: read.event_index,
                source: read.source,
                value: read.value.id(),
                member: &read.location.member,
                proof: read.proof.label(),
                completeness: read.completeness.label(),
                proven_complete: read.is_proven_complete(),
                strong_update: false,
            })
            .collect()
    }

    fn publish(
        context: &RowContext<'_>,
        access: LocatedAccess<'_>,
    ) -> Result<PipelineValue, SiteAdmissionRefusal> {
        let RowContext {
            analyzer,
            declaration,
            seed,
            candidate,
            facts,
            procedure_id,
            admission,
        } = context;
        let record = &access.record;
        let read_site = site_context(
            &candidate.file,
            facts,
            access.site,
            SiteRole::FieldRead {
                member: declaration.unit.fq_name(),
            },
            SiteValue::Unknown(UnknownValueCause::NotConstant),
        );
        let point_id = semantic::program_point_wire_id(record.point);
        let range = access_range(facts, access.site);
        Ok(PipelineValue::FieldRead(Box::new(FieldAccessValue {
            row: CodeQueryFieldRead {
                id: access_id(
                    READ_ID_DOMAIN,
                    &candidate.file,
                    procedure_id,
                    &point_id,
                    record.event_index,
                    &seed.field_id,
                ),
                path: crate::path_utils::workspace_relative_slash_path(candidate.file.rel_path()),
                language: crate::analyzer::common::language_for_file(&candidate.file)
                    .config_label(),
                range: query_range(facts, access.site),
                field_id: seed.field_id.clone(),
                member_fq_name: declaration.unit.fq_name(),
                enclosing: enclosing_name(*analyzer, &candidate.file, &range),
                procedure_id: (*procedure_id).to_owned(),
                program_point_id: point_id,
                site: view(&read_site, admission)?,
                proof: record.proof,
                completeness: record.completeness,
            },
            file: candidate.file.clone(),
            range,
        })))
    }
}

/// Scan one candidate file: its usage scan, then each procedure that encloses a
/// usage, one at a time. No artifact, procedure handle or relation result
/// outlives this call, so the caller may release the file's semantic artifacts
/// right after it. Returns whether a budget or cancellation truncated the file.
#[allow(clippy::too_many_arguments)]
fn scan_file<D: AccessDirection>(
    analyzer: &dyn IAnalyzer,
    semantic: &mut SemanticQueryContext<'_>,
    seed: &Seed<'_>,
    file: &ProjectFile,
    ranges: &[(Range, bool)],
    cancellation: Option<&CancellationToken>,
    rows: &mut Vec<(AccessKey, PipelineValue)>,
) -> bool {
    let step = D::STEP;
    let seed_file = seed.declaration.unit.source();
    let exhausted = false;
    let language = crate::analyzer::common::language_for_file(file);
    let Some(provider) = analyzer
        .structural_fact_providers()
        .into_iter()
        .find(|provider| provider.structural_language() == language)
    else {
        incomplete(
            semantic,
            seed_file,
            format!(
                "{step} has no structural facts for {}, which uses {}",
                rel_path_string(file),
                seed.declaration.unit.fq_name()
            ),
        );
        return exhausted;
    };
    let Some(facts) = provider.structural_facts(file) else {
        incomplete(
            semantic,
            seed_file,
            format!(
                "{step} has no structural facts for {}, which uses {}",
                rel_path_string(file),
                seed.declaration.unit.fq_name()
            ),
        );
        return exhausted;
    };
    let syntax = match provider.structural_syntax_limited(file, facts.source().len(), cancellation) {
        brokk_bifrost_analysis::analyzer::structural::provider::StructuralSyntaxLimitedOutcome::Available(syntax)
            if syntax.prepared().source() == facts.source() =>
        {
            Some(syntax.clone_prepared())
        }
        brokk_bifrost_analysis::analyzer::structural::provider::StructuralSyntaxLimitedOutcome::Exceeded { .. } => {
            semantic.push_diagnostic(
                CodeQueryDiagnosticCode::SemanticBudgetExhausted,
                Incompleteness::Operational(brokk_bifrost_rql::DiagnosticExecutionCause::Budget),
                CodeQueryDiagnosticImpact::Incomplete,
                file,
                &format!(
                    "{step} exceeded syntax preparation budget for {}",
                    rel_path_string(file)
                ),
            );
            None
        }
        _ => {
            incomplete(
                semantic,
                file,
                format!(
                    "{step} has no matching prepared syntax tree for {}",
                    rel_path_string(file)
                ),
            );
            None
        }
    };
    let mut proven = Vec::new();
    let mut unproven = Vec::new();
    for (range, is_proven) in ranges {
        let bytes = (range.start_byte, range.end_byte);
        if *is_proven {
            proven.push(bytes);
        } else {
            unproven.push(bytes);
        }
    }
    proven.sort_unstable();
    proven.dedup();
    unproven.sort_unstable();
    unproven.dedup();
    let mut nodes_by_span = HashMap::default();
    for (id, node) in facts.nodes().iter().enumerate() {
        let span = node.span();
        nodes_by_span
            .entry((span.start_byte, span.end_byte))
            .or_insert(id as u32);
    }
    let file_scan = FileScan {
        facts,
        syntax,
        knowledge: crate::analyzer::languages::language_knowledge(language),
        proven,
        unproven,
        nodes_by_span,
        identity_rows: OnceCell::new(),
    };

    consume_file_scan::<D>(
        analyzer,
        semantic,
        seed,
        file,
        file_scan,
        cancellation,
        rows,
    )
}

/// Join a retained structural scan to this file's semantic revision.
#[allow(clippy::too_many_arguments)]
fn consume_file_scan<D: AccessDirection>(
    analyzer: &dyn IAnalyzer,
    semantic: &mut SemanticQueryContext<'_>,
    seed: &Seed<'_>,
    file: &ProjectFile,
    file_scan: FileScan,
    cancellation: Option<&CancellationToken>,
    rows: &mut Vec<(AccessKey, PipelineValue)>,
) -> bool {
    let step = D::STEP;
    let mut exhausted = false;
    let artifact = match semantic
        .with_cached_artifact(file, |_, _, artifact, _| Arc::clone(artifact))
    {
        Ok(artifact) => artifact,
        Err(refusal) if refusal.is_budget_exhausted() => {
            semantic.push_diagnostic(
                refusal.code(),
                refusal.cause(),
                CodeQueryDiagnosticImpact::Incomplete,
                file,
                &format!(
                    "{step} could not materialize the semantic artifact of {} within the semantic budget",
                    rel_path_string(file)
                ),
            );
            return true;
        }
        Err(refusal) => {
            semantic.push_diagnostic(
                refusal.code(),
                refusal.cause(),
                CodeQueryDiagnosticImpact::Incomplete,
                file,
                &format!(
                    "{step} has no semantic artifact for {}, which uses {}",
                    rel_path_string(file),
                    seed.declaration.unit.fq_name()
                ),
            );
            return exhausted;
        }
    };
    match artifact
        .capabilities()
        .support(SemanticCapability::FieldMemory)
    {
        CapabilitySupport::Complete | CapabilitySupport::Partial => {}
        CapabilitySupport::Unsupported => {
            semantic.push_diagnostic(
                CodeQueryDiagnosticCode::SemanticCapabilityUnsupported,
                Incompleteness::Content,
                CodeQueryDiagnosticImpact::Incomplete,
                file,
                &format!(
                    "{step} needs field-memory semantics, which {} does not support",
                    rel_path_string(file)
                ),
            );
            return exhausted;
        }
    }
    let ranges: Vec<_> = file_scan
        .proven
        .iter()
        .chain(&file_scan.unproven)
        .map(|bytes| access_range(&file_scan.facts, *bytes))
        .collect();
    // Keep census-sized flags while the index is live. Wire IDs and map
    // nodes are allocated only after optional lookup storage is released.
    let mut owner_bits = vec![0_u64; artifact.procedures().len().div_ceil(u64::BITS as usize)];
    let mut unowned_bits = vec![0_u64; ranges.len().div_ceil(u64::BITS as usize)];
    let visitor_bytes = std::mem::size_of_val(&owner_bits)
        + std::mem::size_of_val(&unowned_bits)
        + (owner_bits.capacity() + unowned_bits.capacity()) * std::mem::size_of::<u64>()
        + std::mem::size_of_val(&ranges)
        + ranges.capacity() * std::mem::size_of::<Range>();
    let mut visited = 0;
    let completed = semantic.visit_procedure_candidates_of_source_ranges(
        file,
        &ranges,
        file_scan.facts.source_identity(),
        visitor_bytes,
        |_, procedures| {
            if procedures.is_empty() {
                unowned_bits[visited / u64::BITS as usize] |= 1 << (visited % u64::BITS as usize);
            }
            for procedure in procedures {
                debug_assert!(Arc::ptr_eq(procedure.artifact(), &artifact));
                let index = procedure.id().index();
                owner_bits[index / u64::BITS as usize] |= 1 << (index % u64::BITS as usize);
            }
            visited += 1;
        },
    );
    if completed.is_none() {
        return exhausted;
    }
    assert_eq!(visited, ranges.len());
    if !semantic.charge_consumer_traversal(
        file,
        artifact.procedures().len() + ranges.len(),
        "field owner collection",
    ) {
        return exhausted;
    }
    let found: BTreeMap<_, _> = artifact
        .procedures()
        .iter()
        .filter_map(|procedure| {
            let index = procedure.id().index();
            if owner_bits[index / u64::BITS as usize] & (1 << (index % u64::BITS as usize)) == 0 {
                return None;
            }
            let handle = artifact
                .procedure_handle(procedure.id())
                .expect("validated owner has an artifact-scoped handle");
            Some((semantic::procedure_wire_id(&handle), handle))
        })
        .collect();
    let unowned: Vec<_> = ranges
        .iter()
        .enumerate()
        .filter(|(index, _)| {
            unowned_bits[index / u64::BITS as usize] & (1 << (index % u64::BITS as usize)) != 0
        })
        .map(|(_, range)| format!("{}..{}", range.start_byte, range.end_byte))
        .collect();
    drop(owner_bits);
    drop(unowned_bits);
    if !unowned.is_empty() {
        incomplete_items(
            semantic,
            file,
            format!(
                "{step} found usages of {} in {} outside every lowered procedure, so writes and reads there are not modeled",
                seed.declaration.unit.fq_name(),
                rel_path_string(file)
            ),
            &unowned,
        );
    }
    // Ranking has released its optional index before mandatory executable
    // admission. Deduplicate again because selection can change the wire ID.
    let selected: BTreeMap<_, _> = found
        .into_values()
        .filter_map(|handle| semantic.select_procedure(file, handle))
        .map(|handle| (semantic::procedure_wire_id(&handle), handle))
        .collect();
    for (_, handle) in selected {
        let result = match semantic.property_reaching_of(&handle) {
            Ok(result) => result,
            Err(reason) => {
                // Only a spent budget or a cancellation truncates the row
                // budget; any other reason is an unavailable provider.
                let (code, cause) = match reason {
                    FlowStateIncompleteReason::BudgetExhausted { .. }
                    | FlowStateIncompleteReason::PropertySnapshotBudgetExhausted { .. } => (
                        CodeQueryDiagnosticCode::SemanticBudgetExhausted,
                        brokk_bifrost_rql::DiagnosticExecutionCause::Budget,
                    ),
                    FlowStateIncompleteReason::Cancelled => (
                        CodeQueryDiagnosticCode::Cancelled,
                        brokk_bifrost_rql::DiagnosticExecutionCause::Cancelled,
                    ),
                    _ => (
                        CodeQueryDiagnosticCode::SemanticAnalysisPartial,
                        brokk_bifrost_rql::DiagnosticExecutionCause::Provider,
                    ),
                };
                exhausted |= cause != brokk_bifrost_rql::DiagnosticExecutionCause::Provider;
                semantic.push_diagnostic(
                    code,
                    Incompleteness::Operational(cause),
                    CodeQueryDiagnosticImpact::Incomplete,
                    file,
                    &format!(
                        "{step} could not derive property relations of procedure {}: {reason:?}",
                        semantic::procedure_wire_id(&handle)
                    ),
                );
                continue;
            }
        };
        let candidate = CandidateProcedure {
            label: procedure_label(analyzer, &file_scan.facts, file, &handle),
            file: file.clone(),
            handle,
            result,
        };
        report_procedure_incompleteness(semantic, step, seed, &file_scan, &candidate, &D::IMPACTS);
        let procedure_id = semantic::procedure_wire_id(&candidate.handle);
        let unresolved =
            D::unresolved_dereferences(candidate.handle.semantics(), &candidate.result);
        if !unresolved.is_empty() {
            incomplete_items(
                semantic,
                file,
                format!(
                    "{step} found {} through pointers in procedure {} that are not resolved to a field",
                    D::NOUN,
                    candidate.label
                ),
                &unresolved,
            );
        }
        let located = locate_accesses(
            analyzer,
            cancellation,
            &candidate,
            &file_scan,
            seed,
            D::records(&candidate.result),
        );
        report_located(semantic, step, seed, &candidate, D::NOUN, &located);
        let published: Vec<_> = {
            let admission = semantic.site_admission();
            let context = RowContext {
                analyzer,
                declaration: seed.declaration,
                seed,
                candidate: &candidate,
                facts: &file_scan.facts,
                procedure_id: &procedure_id,
                admission: &admission,
            };
            located
                .accesses
                .into_iter()
                .map(|access| {
                    let key = (
                        rel_path_string(file),
                        access.site,
                        access.record.event_index,
                    );
                    (key, D::publish(&context, access))
                })
                .collect()
        };
        for (key, published) in published {
            match published {
                Ok(value) => rows.push((key, value)),
                Err(refusal) => {
                    exhausted = true;
                    semantic.push_diagnostic(
                        CodeQueryDiagnosticCode::SemanticBudgetExhausted,
                        Incompleteness::Operational(
                            brokk_bifrost_rql::DiagnosticExecutionCause::Budget,
                        ),
                        CodeQueryDiagnosticImpact::Incomplete,
                        file,
                        &format!(
                            "{step} could not retain the source site of a field access in {}: {refusal:?}",
                            rel_path_string(file)
                        ),
                    );
                }
            }
        }
    }
    exhausted
}

/// The accesses of one direction to a field declaration.
///
/// Candidate files are processed one at a time, so a file's semantic
/// artifacts are resident only while its own procedures are scanned.
#[allow(clippy::too_many_arguments)]
fn access_expansions<D: AccessDirection>(
    analyzer: &dyn IAnalyzer,
    semantic: &mut SemanticQueryContext<'_>,
    declaration: &DeclarationValue,
    indexed: &mut IndexedDeclarations,
    reference_cache: &mut ReferenceTraversalCache,
    environment_cache: &mut super::environment::EnvironmentTraversalCache,
    budget: &mut CodeQueryExecutionBudget,
    limits: CodeQueryExecutionLimits,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    max_hits: usize,
    cancellation: Option<&CancellationToken>,
    cache_profile: &mut Option<QueryCacheProfile>,
) -> (Vec<PipelineExpansion>, bool) {
    let step = D::STEP;
    let seed = seed_of(declaration);
    let seed_file = declaration.unit.source().clone();
    // Static memory events have no field selector, so the inherited property
    // projection cannot publish an exhaustive field inventory. Keep scanning
    // and return any rows it can prove, while making the limitation explicit.
    if analyzer
        .signature_metadata(&declaration.unit)
        .into_iter()
        .any(|metadata| metadata.field_is_static())
    {
        semantic.push_diagnostic(
            CodeQueryDiagnosticCode::SemanticCapabilityUnsupported,
            Incompleteness::Content,
            CodeQueryDiagnosticImpact::Incomplete,
            &seed_file,
            &format!(
                "{step} cannot prove an exhaustive static-field memory projection for {} in {}",
                declaration.unit.fq_name(),
                rel_path_string(&seed_file)
            ),
        );
    }
    let (references, mut exhausted) = inbound_reference_expansions(
        analyzer,
        declaration,
        &QueryStep::ReferencesOf(ReferenceTraversalFilter::default()),
        &ReferenceTraversalFilter::default(),
        indexed,
        reference_cache,
        environment_cache,
        budget,
        limits,
        diagnostics,
        max_hits,
        cancellation,
        cache_profile,
    );
    report_unmodeled_field_access_macros(step, analyzer, semantic, &seed, cancellation);
    let mut usage_ranges: BTreeMap<ProjectFile, Vec<(Range, bool)>> = BTreeMap::new();
    for expansion in &references {
        let PipelineValue::ReferenceSite(site) = &expansion.value else {
            unreachable!("references_of expands to reference sites");
        };
        usage_ranges
            .entry(site.file.clone())
            .or_default()
            .push((site.range, site.proof == UsageProof::Proven));
    }
    let mut unproven_sites = Vec::new();
    for (file, ranges) in &usage_ranges {
        for (range, is_proven) in ranges {
            if !*is_proven {
                unproven_sites.push(format!(
                    "{}:{}..{}",
                    rel_path_string(file),
                    range.start_byte,
                    range.end_byte
                ));
            }
        }
    }
    if !unproven_sites.is_empty() {
        unproven_sites.sort_unstable();
        incomplete_items(
            semantic,
            &seed_file,
            format!(
                "{step} cannot prove {} usage sites of {} refer to it, so writes and reads matched there have unproven target identity",
                unproven_sites.len(),
                declaration.unit.fq_name()
            ),
            &unproven_sites,
        );
    }

    // The result rows retain source sites and values, not semantic artifacts,
    // so release artifacts after each candidate file is scanned.
    let mut rows = Vec::new();
    for (file, ranges) in &usage_ranges {
        exhausted |= scan_file::<D>(
            analyzer,
            semantic,
            &seed,
            file,
            ranges,
            cancellation,
            &mut rows,
        );
        semantic.release_unreferenced_artifacts();
    }
    rows.sort_by(|left, right| left.0.cmp(&right.0));
    let expansions = rows
        .into_iter()
        .map(|(_, value)| pipeline_expansion(value))
        .collect();
    (expansions, exhausted)
}

/// The writes to a field declaration.
#[allow(clippy::too_many_arguments)]
pub(super) fn field_write_expansions(
    analyzer: &dyn IAnalyzer,
    semantic: &mut SemanticQueryContext<'_>,
    declaration: &DeclarationValue,
    indexed: &mut IndexedDeclarations,
    reference_cache: &mut ReferenceTraversalCache,
    environment_cache: &mut super::environment::EnvironmentTraversalCache,
    budget: &mut CodeQueryExecutionBudget,
    limits: CodeQueryExecutionLimits,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    max_hits: usize,
    cancellation: Option<&CancellationToken>,
    cache_profile: &mut Option<QueryCacheProfile>,
) -> (Vec<PipelineExpansion>, bool) {
    access_expansions::<Writes>(
        analyzer,
        semantic,
        declaration,
        indexed,
        reference_cache,
        environment_cache,
        budget,
        limits,
        diagnostics,
        max_hits,
        cancellation,
        cache_profile,
    )
}

/// The reads of a field declaration.
#[allow(clippy::too_many_arguments)]
pub(super) fn field_read_expansions(
    analyzer: &dyn IAnalyzer,
    semantic: &mut SemanticQueryContext<'_>,
    declaration: &DeclarationValue,
    indexed: &mut IndexedDeclarations,
    reference_cache: &mut ReferenceTraversalCache,
    environment_cache: &mut super::environment::EnvironmentTraversalCache,
    budget: &mut CodeQueryExecutionBudget,
    limits: CodeQueryExecutionLimits,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    max_hits: usize,
    cancellation: Option<&CancellationToken>,
    cache_profile: &mut Option<QueryCacheProfile>,
) -> (Vec<PipelineExpansion>, bool) {
    access_expansions::<Reads>(
        analyzer,
        semantic,
        declaration,
        indexed,
        reference_cache,
        environment_cache,
        budget,
        limits,
        diagnostics,
        max_hits,
        cancellation,
        cache_profile,
    )
}

#[cfg(test)]
mod revision_tests {
    use super::*;
    use crate::analyzer::{AnalyzerConfig, OverlayProject, TestProject, WorkspaceAnalyzer};
    use crate::structural::CodeQuery;
    use brokk_bifrost_test_macros::hardwon;
    use serde_json::json;

    #[test]
    #[hardwon(
        "#14365: field access verified the semantic artifact against itself, not the structural facts' revision"
    )]
    fn field_access_rejects_a_newer_semantic_revision_than_its_scan() {
        let original =
            "class Example { int value; void run() { this.value = 1; this.value = 1; } }\n";
        let changed =
            "class Example { int value; void run() { this.value = 2; this.value = 2; } }\n";
        assert_eq!(original.len(), changed.len());
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical root");
        let file = ProjectFile::new(root.clone(), "Example.java");
        file.write(original).expect("write original source");
        let overlay = Arc::new(OverlayProject::new(Arc::new(TestProject::new(
            root,
            Language::Java,
        ))));
        let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
            Arc::clone(&overlay) as Arc<dyn crate::analyzer::Project>,
            AnalyzerConfig::default(),
        )
        .expect("workspace");
        let provider = workspace
            .analyzer()
            .structural_fact_providers()
            .into_iter()
            .find(|provider| provider.structural_language() == Language::Java)
            .expect("Java provider");
        let facts = provider.structural_facts(&file).expect("revision A facts");
        let query = CodeQuery::from_json(&json!({
            "match": { "kind": "declaration", "name": "value" }
        }))
        .expect("field seed query");
        let fact_match =
            super::super::super::matcher::match_query(query.seed().expect("seed"), &facts, 1)
                .into_iter()
                .next()
                .expect("field declaration");
        let structural_seed = SeedMatch {
            language: Language::Java,
            file: file.clone(),
            facts: Arc::clone(&facts),
            fact_match,
            python_import: None,
        };
        let (declaration, omitted) = enclosing_declaration_value(
            workspace.analyzer(),
            &structural_seed,
            &mut HashMap::default(),
        );
        assert!(!omitted);
        let declaration = declaration.expect("field declaration projection");
        let seed = seed_of(&declaration);
        let make_scan = || FileScan {
            facts: Arc::clone(&facts),
            syntax: None,
            knowledge: crate::analyzer::languages::language_knowledge(Language::Java),
            proven: facts
                .nodes()
                .iter()
                .enumerate()
                .filter(|(_, node)| node.kind == NormalizedKind::FieldAccess)
                .map(|(id, _)| member_token_bytes(&facts, id as u32).expect("field member token"))
                .collect(),
            unproven: Vec::new(),
            nodes_by_span: facts
                .nodes()
                .iter()
                .enumerate()
                .map(|(id, node)| ((node.range.start_byte, node.range.end_byte), id as u32))
                .collect(),
            identity_rows: OnceCell::new(),
        };
        assert_eq!(make_scan().proven.len(), 2);
        let mut positive = SemanticQueryContext::new(
            &workspace,
            None,
            CodeQueryExecutionLimits::default().semantic,
        );
        let mut rows = Vec::new();
        assert!(!consume_file_scan::<Writes>(
            workspace.analyzer(),
            &mut positive,
            &seed,
            &file,
            make_scan(),
            None,
            &mut rows,
        ));
        assert_eq!(
            rows.len(),
            2,
            "same-revision field writes must publish; declaration={declaration:?}; diagnostics={:?}",
            positive.take_diagnostics()
        );
        drop(positive);

        assert!(overlay.set(file.abs_path(), changed.to_owned()));
        let mut semantic = SemanticQueryContext::new(
            &workspace,
            None,
            CodeQueryExecutionLimits::default().semantic,
        );
        // This assertion is a non-vacuity gate: earlier source projection
        // refusal must not masquerade as exercising the field join.
        let artifact_identity = semantic
            .with_cached_artifact(&file, |_, _, artifact, _| {
                artifact.key().revision().content()
            })
            .expect("revision B must reach the field join, without earlier source refusal");
        assert_ne!(facts.source_identity(), artifact_identity);
        rows.clear();
        assert!(!consume_file_scan::<Writes>(
            workspace.analyzer(),
            &mut semantic,
            &seed,
            &file,
            make_scan(),
            None,
            &mut rows,
        ));
        let diagnostics = semantic.take_diagnostics();
        assert!(
            rows.is_empty(),
            "mixed revisions must not publish a field row"
        );
        assert_eq!(
            diagnostics
                .iter()
                .filter(|diagnostic| {
                    diagnostic.code == CodeQueryDiagnosticCode::SemanticResultsOmitted
                        && diagnostic.incompleteness
                            == Incompleteness::Operational(
                                brokk_bifrost_rql::DiagnosticExecutionCause::Snapshot,
                            )
                })
                .count(),
            1,
            "one snapshot refusal per file: {diagnostics:?}",
        );
        assert!(
            diagnostics.iter().any(|diagnostic| {
                diagnostic.code == CodeQueryDiagnosticCode::SemanticResultsOmitted
                    && diagnostic.incompleteness
                        == Incompleteness::Operational(
                            brokk_bifrost_rql::DiagnosticExecutionCause::Snapshot,
                        )
                    && diagnostic.impact == CodeQueryDiagnosticImpact::Incomplete
            }),
            "expected Snapshot incompleteness: {diagnostics:?}"
        );
    }
    #[test]
    #[hardwon("#14365: field accesses rescanned every procedure for each usage range")]
    fn field_access_procedure_lookup_avoids_the_procedure_usage_cross_product() {
        let mut receipts = Vec::new();
        for methods in [128, 512] {
            let mut source = String::from("class Example { int value = 0;\n");
            for method in 0..methods {
                source.push_str(&format!("void m{method}() {{ this.value = 1; }}\n"));
            }
            source.push_str("}\n");
            let temp = tempfile::tempdir().expect("temp dir");
            let root = temp.path().canonicalize().expect("canonical root");
            let file = ProjectFile::new(root.clone(), "Example.java");
            file.write(&source).expect("write sibling-method corpus");
            let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
                Arc::new(TestProject::new(root, Language::Java)),
                AnalyzerConfig::default(),
            )
            .expect("workspace");
            let provider = workspace
                .analyzer()
                .structural_fact_providers()
                .into_iter()
                .find(|provider| provider.structural_language() == Language::Java)
                .expect("Java provider");
            let facts = provider.structural_facts(&file).expect("structural facts");
            let ranges: Vec<_> = facts
                .nodes()
                .iter()
                .filter(|node| node.kind == NormalizedKind::FieldAccess)
                .map(|node| node.range)
                .collect();
            assert_eq!(ranges.len(), methods);
            let mut semantic = SemanticQueryContext::new(
                &workspace,
                None,
                CodeQueryExecutionLimits::default().semantic,
            );
            let mut visited = 0;
            semantic
                .visit_procedure_candidates_of_source_ranges(
                    &file,
                    &ranges,
                    facts.source_identity(),
                    0,
                    |_, candidates| {
                        assert_eq!(candidates.len(), 1);
                        visited += 1;
                    },
                )
                .expect("same-revision range batch");
            assert_eq!(visited, ranges.len());
            let work = semantic.work();
            let cross_product = work.procedures * ranges.len() as u64;
            let mut isolated = SemanticQueryContext::new(
                &workspace,
                None,
                CodeQueryExecutionLimits::default().semantic,
            );
            let single =
                isolated.procedure_of_source_range(&file, ranges[0], facts.source_identity());
            assert_eq!(single.len(), 1);
            let isolated_visits = isolated.work().traversal_steps;
            assert!(
                isolated_visits <= 2 * work.procedures + 8,
                "an isolated lookup must scan once without constructing an index: procedures={}, visits={isolated_visits}",
                work.procedures,
            );
            eprintln!(
                "#14365 isolated lookup (methods={methods}, procedures={}, visits={isolated_visits})",
                work.procedures
            );
            for sparse_count in [1, 2] {
                let mut sparse = SemanticQueryContext::new(
                    &workspace,
                    None,
                    CodeQueryExecutionLimits::default().semantic,
                );
                let mut sparse_visited = 0;
                sparse
                    .visit_procedure_candidates_of_source_ranges(
                        &file,
                        &ranges[..sparse_count],
                        facts.source_identity(),
                        0,
                        |_, candidates| {
                            assert_eq!(candidates.len(), 1);
                            sparse_visited += 1;
                        },
                    )
                    .expect("same-revision sparse field scan");
                assert_eq!(sparse_visited, sparse_count);
                let sparse_visits = sparse.work().traversal_steps;
                assert!(
                    sparse_visits <= sparse_count as u64 * (2 * work.procedures + 8),
                    "a sparse field scan must not build an index: procedures={}, usages={sparse_count}, visits={sparse_visits}",
                    work.procedures
                );
                eprintln!(
                    "#14365 sparse field scan (methods={methods}, procedures={}, usages={sparse_count}, visits={sparse_visits})",
                    work.procedures
                );
            }
            receipts.push((
                methods,
                work.procedures,
                work.traversal_steps,
                cross_product,
            ));
            assert!(
                work.traversal_steps * 2 < cross_product,
                "one indexed batch must avoid the per-usage procedure scan: {receipts:?}"
            );
        }
        assert!(
            receipts[1].2 < receipts[0].2 * 6,
            "quadrupling siblings/usages must not square visits: {receipts:?}"
        );
        eprintln!(
            "#14365 Java sibling-method corpus (methods, procedures, indexed visits, old procedure/usage pairs): {receipts:?}"
        );
    }

    #[test]
    #[hardwon("#14365: nested field usages retained every enclosing candidate for every usage")]
    fn field_access_nested_ranges_release_candidates_before_the_next_usage() {
        let depth = 16;
        let usages = 128;
        let mut source = String::from("class Box { value = 0; }\n");
        for level in 0..depth {
            if level == 0 {
                source.push_str("function f0(box: Box) {\n");
            } else {
                source.push_str(&format!("function f{level}() {{\n"));
            }
        }
        for _ in 0..usages {
            source.push_str("box.value = 1;\n");
        }
        for level in (0..depth).rev() {
            source.push_str("}\n");
            if level > 0 {
                source.push_str(&format!("f{level}();\n"));
            }
        }
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical root");
        let file = ProjectFile::new(root.clone(), "app.ts");
        file.write(&source).expect("write nested-callable corpus");
        let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
            Arc::new(TestProject::new(root, Language::TypeScript)),
            AnalyzerConfig::default(),
        )
        .expect("workspace");
        let provider = workspace
            .analyzer()
            .structural_fact_providers()
            .into_iter()
            .find(|provider| provider.structural_language() == Language::TypeScript)
            .expect("TypeScript provider");
        let facts = provider.structural_facts(&file).expect("structural facts");
        let ranges: Vec<_> = facts
            .nodes()
            .iter()
            .filter(|node| node.kind == NormalizedKind::FieldAccess)
            .map(|node| node.range)
            .collect();
        assert_eq!(ranges.len(), usages);
        let mut semantic = SemanticQueryContext::new(
            &workspace,
            None,
            CodeQueryExecutionLimits::default().semantic,
        );
        let warm = semantic.procedure_of_source_range(&file, ranges[0], facts.source_identity());
        assert_eq!(warm.len(), 1);
        drop(warm);
        let artifact = semantic
            .with_cached_artifact(&file, |_, _, artifact, _| Arc::clone(artifact))
            .expect("nested artifact");
        let raw = crate::analyzer::semantic::workspace_oracle::procedures_for_source_ranges(
            &artifact,
            &ranges[..1],
            usize::MAX,
            &CancellationToken::new(),
        );
        let overlapping = raw.handles.len();
        assert!(
            overlapping >= depth,
            "fixture must reach overlapping enclosing candidates: depth={depth}, candidates={overlapping}"
        );
        // Nested candidates coexist with the extent/tree storage, and
        // smallest-owner ranking can clone their handles before pruning.
        // The old construction-only reservation cannot cover even this
        // directly measurable lower bound of the live lookup footprint.
        {
            use crate::analyzer::semantic::workspace_oracle::dispatch::{
                ProcedureLookupProgress, ProcedureSourceRangeIndex,
            };
            let cancellation = CancellationToken::new();
            let mut progress = ProcedureLookupProgress::new(usize::MAX, &cancellation);
            let index = ProcedureSourceRangeIndex::new(&artifact, &mut progress)
                .expect("nested procedure index");
            let handles = index
                .lookup(&ranges[0], &mut progress)
                .expect("nested candidate lookup");
            assert_eq!(handles.len(), overlapping);
            let live_lower_bound = index.retained_bytes()
                + 2 * handles.capacity() * std::mem::size_of::<ProcedureHandle>();
            assert!(
                ProcedureSourceRangeIndex::reservation_bytes(artifact.procedures().len())
                    .expect("nested index grant")
                    >= live_lower_bound,
                "index admission must cover live candidate handles and their ranking clone"
            );
        }
        drop(raw);
        let baseline = Arc::strong_count(&artifact);
        let mut peak = baseline;
        let mut selected = HashSet::new();
        let mut visited = 0;
        semantic
            .visit_procedure_candidates_of_source_ranges(
                &file,
                &ranges,
                facts.source_identity(),
                0,
                |_, candidates| {
                    assert_eq!(candidates.len(), 1);
                    peak = peak.max(Arc::strong_count(&artifact));
                    selected.insert(semantic::procedure_wire_id(&candidates[0]));
                    visited += 1;
                },
            )
            .expect("same-revision nested ranges");
        assert_eq!(visited, usages);
        assert_eq!(selected.len(), 1);
        assert!(
            peak <= baseline + 2 * depth + 8,
            "candidate retention must follow nesting depth, not usages times depth: baseline={baseline}, peak={peak}, depth={depth}, usages={usages}"
        );
        eprintln!(
            "#14365 nested TypeScript candidate retention (depth={depth}, usages={usages}, overlapping candidates={overlapping}, baseline artifact references={baseline}, peak={peak})"
        );
    }
}
