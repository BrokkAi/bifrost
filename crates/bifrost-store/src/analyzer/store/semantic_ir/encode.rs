//! Lowered procedures to row vectors, one vector of cells per table.

use rusqlite::types::Value;

use super::Table;
use super::codes::{
    AllocationKindTag, ArgumentDomainTag, BackingStoreOffsetTag, CallableReferenceKindTag,
    CallableTargetTag, CaptureModeTag, CaptureSourceTag, CompletenessTag, ContinuationTag,
    DropBehaviorTag, EffectTag, ExpansionTag, GapSubjectTag, GuardPredicateTag, HeapSelectorTag,
    IncompleteReasonTag, IncompleteSubjectTag, MemoryLocationKindTag, MemoryValueCopyTag,
    MultiplicityTag, PartialPortTag, PlaceTag, PointerAccessWidthTag, PointerByteOffsetTag,
    PointerInvalidationTargetTag, PointerOriginKindTag, ProofTag, RowCode, ScopeEndAtTag,
    SynchronizationPayloadCopyTag, SynchronizationPayloadTag, TargetResolutionTag, TransferKindTag,
    TransferOperationTag, ValueFlowKindTag, ValueKindTag,
};
use crate::analyzer::semantic::partial_flow::fixpoint::ProcedurePartialFlows;
use crate::analyzer::semantic::partial_flow::ports::{HeapSelector, PartialFlowPort};
use crate::analyzer::semantic::{
    AllocationKind, ArgumentDomain, BackingStoreOffset, CallArgumentExpansion,
    CallableReferenceKind, CallableTarget, CallableTargetResolution, CaptureMode, CaptureSource,
    ContentIdentity, ControlContinuation, DeclarationLocator, DropBehavior, EvidenceCompleteness,
    FormalMultiplicity, GuardArm, GuardPredicate, MemoryLocationKind, MemoryValueCopy,
    PointerAccessWidth, PointerByteOffset, PointerInvalidationTarget, PointerOriginKind,
    ProcedureSemanticsParts, ProofStatus, ScopeEndAt, SemanticEffect, SemanticGapSubject,
    SemanticIncompleteReason, SemanticIncompleteSubject, SemanticLanguage, SemanticLocator,
    SemanticPlace, SemanticRole, SemanticValueKind, SourceAnchor, SwitchEdgeParts,
    SynchronizationPayload, SynchronizationPayloadCopy, TransferKind, TransferOperation,
    ValueFlowKind, WorkspaceMountId, WorkspaceRelativePath,
};
use crate::hash::HashMap;

/// The cells of every child table, row-major, in each table's column order.
#[derive(Debug, PartialEq)]
pub(super) struct EncodedRows {
    cells: [Vec<Value>; Table::COUNT],
    /// The payload estimate per table.
    payload_bytes: [usize; Table::COUNT],
}

impl Default for EncodedRows {
    fn default() -> Self {
        Self {
            cells: std::array::from_fn(|_| Vec::new()),
            payload_bytes: [0; Table::COUNT],
        }
    }
}

impl EncodedRows {
    fn push(&mut self, table: Table, row: Vec<Value>) {
        let spec = table.spec();
        assert_eq!(
            row.len(),
            spec.columns.len(),
            "{} row has {} cells for columns {:?}",
            spec.name,
            row.len(),
            spec.columns
        );
        self.payload_bytes[table as usize] += row
            .iter()
            .map(|cell| match cell {
                Value::Null => 0,
                Value::Integer(_) | Value::Real(_) => 4,
                Value::Text(text) => text.len(),
                Value::Blob(bytes) => bytes.len(),
            })
            .sum::<usize>();
        self.cells[table as usize].extend(row);
    }

    pub(super) fn cells(&self, table: Table) -> &[Value] {
        &self.cells[table as usize]
    }

    pub(super) fn rows(&self, table: Table) -> usize {
        self.cells[table as usize].len() / table.spec().columns.len()
    }

    pub(super) fn row_count(&self) -> usize {
        Table::ALL.iter().map(|table| self.rows(*table)).sum()
    }

    pub(super) fn payload_bytes(&self) -> usize {
        self.payload_bytes.iter().sum()
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(super) fn table_payload_bytes(&self, table: Table) -> usize {
        self.payload_bytes[table as usize]
    }
}

pub(super) struct Encoded {
    pub(super) rows: EncodedRows,
    /// JSON array of the artifact's Go builtin names, sorted, without
    /// duplicates.
    pub(super) go_predeclared_builtins: String,
}

/// Encode validated procedures. `content` is the blob's content identity;
/// every structural node identity in the parts must carry it.
pub(super) fn encode<'a>(
    parts: &'a [ProcedureSemanticsParts],
    partial_flows: Option<&'a [ProcedurePartialFlows]>,
    content: ContentIdentity,
) -> Encoded {
    let mut encoder = Encoder {
        rows: EncodedRows::default(),
        texts: HashMap::default(),
        declarations: HashMap::default(),
        locators: HashMap::default(),
        scope: parts.first().map(|procedure| {
            let locator = &procedure.locator;
            (locator.mount(), locator.path(), locator.language())
        }),
        content,
        next_group: 0,
    };
    for (index, procedure) in parts.iter().enumerate() {
        assert_eq!(
            procedure.id.index(),
            index,
            "semantic IR procedure {index} carries id {}",
            procedure.id
        );
        assert!(
            procedure.source_range_holes.is_empty(),
            "query-time source ownership holes cannot be persisted as IR rows: {:?}",
            procedure.source_range_holes,
        );
        encoder.procedure(procedure);
    }
    if let Some(flows) = partial_flows {
        assert_eq!(
            flows.len(),
            parts.len(),
            "partial flows are given for every procedure"
        );
        for (index, procedure_flows) in flows.iter().enumerate() {
            encoder.partial_flows(
                u32::try_from(index).expect("a procedure index fits u32"),
                procedure_flows,
            );
        }
    }
    let mut builtins = parts
        .iter()
        .flat_map(|procedure| procedure.go_predeclared_builtin_assumptions.iter())
        .map(|builtin| builtin.name())
        .collect::<Vec<_>>();
    builtins.sort_unstable();
    builtins.dedup();
    Encoded {
        rows: encoder.rows,
        go_predeclared_builtins: serde_json::to_string(&builtins).expect("builtin names serialize"),
    }
}

struct Encoder<'a> {
    rows: EncodedRows,
    texts: HashMap<&'a str, i64>,
    declarations: HashMap<&'a DeclarationLocator, i64>,
    locators: HashMap<(Option<i64>, i64, SemanticRole, SourceAnchor), i64>,
    /// The artifact's mount, path and language. Every stored locator shares
    /// the mount and language; a locator stores its path only when it is not
    /// this one.
    scope: Option<(
        WorkspaceMountId,
        &'a WorkspaceRelativePath,
        SemanticLanguage,
    )>,
    content: ContentIdentity,
    /// The next callable target group of the current procedure.
    next_group: i64,
}

fn integer(value: impl Into<u32>) -> Value {
    Value::Integer(i64::from(value.into()))
}

fn optional<T: Into<u32>>(value: Option<T>) -> Value {
    value.map_or(Value::Null, integer)
}

fn code<T: RowCode>(value: T) -> Value {
    Value::Integer(value.code())
}

fn flag(value: bool) -> Value {
    Value::Integer(i64::from(value))
}

fn some(value: i64) -> Value {
    Value::Integer(value)
}

fn decimal(value: impl ToString) -> Value {
    Value::Text(value.to_string())
}

fn json_ids(ids: impl Iterator<Item = i64>) -> Value {
    Value::Text(serde_json::to_string(&ids.collect::<Vec<_>>()).expect("integer array serializes"))
}

fn anchor(anchor: SourceAnchor) -> [Value; 7] {
    let span = anchor.span();
    [
        integer(span.start().byte_offset()),
        integer(span.start().line()),
        integer(span.start().byte_column()),
        integer(span.end().byte_offset()),
        integer(span.end().line()),
        integer(span.end().byte_column()),
        integer(anchor.occurrence()),
    ]
}

fn continuation(value: ControlContinuation) -> [Value; 2] {
    [code(ContinuationTag::of(&value)), optional(value.target())]
}

fn arm(arm: Option<GuardArm>) -> [Value; 2] {
    match arm {
        Some(arm) => [integer(arm.target_point), code(arm.kind)],
        None => [Value::Null, Value::Null],
    }
}

/// Event columns after `effect`, in table order.
#[derive(Default)]
struct EventCells {
    sub_kind: Option<i64>,
    value_a: Option<u32>,
    value_b: Option<u32>,
    value_c: Option<u32>,
    location: Option<u32>,
    allocation: Option<u32>,
    call_site: Option<u32>,
    capture: Option<u32>,
    gap: Option<u32>,
    locator: Option<i64>,
    suspend_point: Option<u32>,
}

impl<'a> Encoder<'a> {
    fn text(&mut self, text: &'a str) -> i64 {
        if let Some(id) = self.texts.get(text) {
            return *id;
        }
        let id = i64::try_from(self.texts.len()).expect("text count fits i64");
        self.texts.insert(text, id);
        self.rows
            .push(Table::Texts, vec![some(id), Value::Text(text.to_owned())]);
        id
    }

    fn optional_text(&mut self, text: Option<&'a str>) -> Value {
        text.map_or(Value::Null, |text| some(self.text(text)))
    }

    fn declaration(&mut self, declaration: &'a DeclarationLocator) -> i64 {
        if let Some(id) = self.declarations.get(declaration) {
            return *id;
        }
        let id = i64::try_from(self.declarations.len()).expect("declaration count fits i64");
        self.declarations.insert(declaration, id);
        for (ordinal, segment) in declaration.segments().iter().enumerate() {
            let name = self.optional_text(segment.name());
            let mut row = vec![
                some(id),
                some(i64::try_from(ordinal).expect("segment ordinal fits i64")),
                code(segment.kind()),
                name,
            ];
            row.extend(anchor(segment.anchor()));
            row.push(integer(segment.sibling_ordinal()));
            self.rows.push(Table::DeclarationSegments, row);
        }
        id
    }

    fn locator(&mut self, locator: &'a SemanticLocator) -> i64 {
        let (mount, path, language) = self
            .scope
            .expect("a locator belongs to a procedure, so the scope is known");
        assert!(
            locator.mount() == mount && locator.language() == language,
            "semantic IR rows store locators without mount or language, but {locator:?} \
             is outside the artifact's mount {mount} ({language:?})"
        );
        let locator_path = (locator.path() != path).then(|| self.text(locator.path().as_str()));
        let declaration = self.declaration(locator.declaration());
        let key = (locator_path, declaration, locator.role(), locator.anchor());
        if let Some(id) = self.locators.get(&key) {
            return *id;
        }
        let id = i64::try_from(self.locators.len()).expect("locator count fits i64");
        self.locators.insert(key, id);
        let mut row = vec![
            some(id),
            locator_path.map_or(Value::Null, some),
            some(declaration),
            code(locator.role()),
        ];
        row.extend(anchor(locator.anchor()));
        self.rows.push(Table::Locators, row);
        id
    }

    /// Store a non-empty candidate list as the procedure's next target
    /// group, or `None` for an empty one.
    fn target_group(&mut self, procedure: u32, candidates: &'a [CallableTarget]) -> Value {
        if candidates.is_empty() {
            return Value::Null;
        }
        let group = self.next_group;
        self.next_group += 1;
        for (ordinal, target) in candidates.iter().enumerate() {
            let (local_procedure, locator, artifact_identity) = match target {
                CallableTarget::Local(local) => (integer(*local), Value::Null, Value::Null),
                CallableTarget::Unmaterialized(locator) | CallableTarget::External(locator) => {
                    (Value::Null, some(self.locator(locator)), Value::Null)
                }
                CallableTarget::Artifact(artifact) => (
                    Value::Null,
                    Value::Null,
                    Value::Text(
                        serde_json::to_string(artifact.identity())
                            .expect("anonymous callable identity serializes"),
                    ),
                ),
            };
            self.rows.push(
                Table::CallableTargets,
                vec![
                    integer(procedure),
                    some(group),
                    some(i64::try_from(ordinal).expect("target ordinal fits i64")),
                    code(CallableTargetTag::of(target)),
                    local_procedure,
                    locator,
                    artifact_identity,
                ],
            );
        }
        some(group)
    }

    fn resolution(
        &mut self,
        procedure: u32,
        resolution: &'a CallableTargetResolution,
    ) -> [Value; 2] {
        [
            code(TargetResolutionTag::of(resolution)),
            self.target_group(procedure, resolution.candidates()),
        ]
    }

    fn place(&mut self, place: &'a SemanticPlace) -> [Value; 3] {
        let tag = code(PlaceTag::of(place));
        match place {
            SemanticPlace::LocalBinding(locator) => [tag, some(self.locator(locator)), Value::Null],
            SemanticPlace::MemoryLocation(location) => [tag, Value::Null, integer(*location)],
        }
    }

    fn procedure(&mut self, procedure: &'a ProcedureSemanticsParts) {
        let id = procedure.id.get();
        self.next_group = 0;
        let locator = self.locator(&procedure.locator);
        let properties = procedure.properties;
        self.rows.push(
            Table::Procedures,
            vec![
                integer(id),
                some(locator),
                optional(procedure.lexical_parent),
                code(procedure.kind),
                flag(properties.is_async),
                flag(properties.is_generator),
                flag(properties.is_static),
                flag(properties.is_synthetic),
                code(properties.invocation),
                code(properties.dispatch_extensibility),
                code(properties.call_boundary),
                code(properties.receiver_binding),
                code(properties.construction_return),
                integer(procedure.source),
                integer(procedure.evidence),
            ],
        );
        self.values(procedure);
        self.allocations(procedure);
        self.memory_locations(procedure);
        self.captures(procedure);
        // Target groups are numbered over call sites, then events, then
        // drops; the order of these three calls is that numbering.
        self.call_sites(procedure);
        self.source_mappings(procedure);
        self.sites(procedure);
        self.evidence(procedure);
        self.gaps(procedure);
        self.blocks_and_points(procedure);
        self.control_edges(procedure);
        self.guard_facts(procedure);
        self.switch_facts(procedure);
        self.lifecycle(procedure);
        self.pointers(procedure);
        self.receiver_type_facts(procedure);
    }

    fn values(&mut self, procedure: &'a ProcedureSemanticsParts) {
        let id = procedure.id.get();
        for (index, value) in procedure.values.iter().enumerate() {
            assert_eq!(value.id.index(), index, "procedure {id} value {index}");
            let mut ordinal = Value::Null;
            let mut multiplicity = Value::Null;
            let mut rest_domain = Value::Null;
            let mut rest_domain_text = Value::Null;
            let mut name = Value::Null;
            let mut passing_mode = Value::Null;
            let mut value_flag = Value::Null;
            let mut magnitude = Value::Null;
            let mut float_bits = Value::Null;
            let mut text = Value::Null;
            match &value.kind {
                SemanticValueKind::Parameter {
                    ordinal: parameter_ordinal,
                    multiplicity: parameter_multiplicity,
                    name: parameter_name,
                    passing_mode: parameter_passing_mode,
                } => {
                    ordinal = integer(*parameter_ordinal);
                    multiplicity = code(MultiplicityTag::of(parameter_multiplicity));
                    if let FormalMultiplicity::Rest(domain) = parameter_multiplicity {
                        [rest_domain, rest_domain_text] = self.domain(domain);
                    }
                    name = self.optional_text(parameter_name.as_deref());
                    passing_mode = code(*parameter_passing_mode);
                }
                SemanticValueKind::DefaultArgument {
                    ordinal: default_ordinal,
                } => ordinal = integer(*default_ordinal),
                SemanticValueKind::Receiver { dispatch } => value_flag = flag(*dispatch),
                SemanticValueKind::Boolean(constant) => value_flag = flag(*constant),
                SemanticValueKind::UnsignedInteger(constant) => magnitude = decimal(constant),
                SemanticValueKind::SignedInteger(constant) => magnitude = decimal(constant),
                SemanticValueKind::FloatingPoint { bits } => {
                    float_bits = some(i64::from_ne_bytes(bits.to_ne_bytes()));
                }
                SemanticValueKind::ConstantString(constant)
                | SemanticValueKind::LanguageDefined(constant) => {
                    text = some(self.text(constant));
                }
                SemanticValueKind::Local
                | SemanticValueKind::Return
                | SemanticValueKind::Temporary
                | SemanticValueKind::Address
                | SemanticValueKind::Null
                | SemanticValueKind::Constant
                | SemanticValueKind::Exception
                | SemanticValueKind::Callable
                | SemanticValueKind::AwaitResult => {}
            }
            self.rows.push(
                Table::Values,
                vec![
                    integer(id),
                    integer(value.id),
                    code(ValueKindTag::of(&value.kind)),
                    ordinal,
                    multiplicity,
                    rest_domain,
                    rest_domain_text,
                    name,
                    passing_mode,
                    value_flag,
                    magnitude,
                    float_bits,
                    text,
                    integer(value.source),
                    integer(value.evidence),
                ],
            );
        }
    }

    /// An argument domain's code and, for a language-defined domain, its
    /// text id.
    fn domain(&mut self, domain: &'a ArgumentDomain) -> [Value; 2] {
        let text = match domain {
            ArgumentDomain::LanguageDefined(text) => some(self.text(text)),
            ArgumentDomain::Positional
            | ArgumentDomain::Keyword
            | ArgumentDomain::PositionalOrKeyword => Value::Null,
        };
        [code(ArgumentDomainTag::of(domain)), text]
    }

    fn allocations(&mut self, procedure: &'a ProcedureSemanticsParts) {
        let id = procedure.id.get();
        for (index, allocation) in procedure.allocations.iter().enumerate() {
            assert_eq!(
                allocation.id.index(),
                index,
                "procedure {id} allocation {index}"
            );
            let kind_text = match &allocation.kind {
                AllocationKind::LanguageDefined(text) => some(self.text(text)),
                _ => Value::Null,
            };
            self.rows.push(
                Table::Allocations,
                vec![
                    integer(id),
                    integer(allocation.id),
                    integer(allocation.point),
                    integer(allocation.result),
                    code(AllocationKindTag::of(&allocation.kind)),
                    kind_text,
                    integer(allocation.source),
                    integer(allocation.evidence),
                ],
            );
        }
    }

    fn memory_locations(&mut self, procedure: &'a ProcedureSemanticsParts) {
        let id = procedure.id.get();
        for (index, location) in procedure.memory_locations.iter().enumerate() {
            assert_eq!(
                location.id.index(),
                index,
                "procedure {id} memory location {index}"
            );
            let mut base = Value::Null;
            let mut member = Value::Null;
            let mut property_key = Value::Null;
            let mut index_value = Value::Null;
            let mut constant_index = Value::Null;
            let mut index_identity = Value::Null;
            let mut lexical_parent = Value::Null;
            let mut binding = Value::Null;
            match &location.kind {
                MemoryLocationKind::Field {
                    base: field_base,
                    member: field_member,
                } => {
                    base = integer(*field_base);
                    member = some(self.locator(field_member));
                }
                MemoryLocationKind::Property {
                    base: property_base,
                    key,
                } => {
                    base = integer(*property_base);
                    property_key = some(self.text(key));
                }
                MemoryLocationKind::Static {
                    member: static_member,
                } => member = some(self.locator(static_member)),
                MemoryLocationKind::Index {
                    base: index_base,
                    index,
                    constant_index: constant,
                    identity,
                } => {
                    base = integer(*index_base);
                    index_value = optional(*index);
                    constant_index = constant.map_or(Value::Null, decimal);
                    index_identity = code(*identity);
                }
                MemoryLocationKind::Dereference { address } => base = integer(*address),
                MemoryLocationKind::LexicalCell {
                    binding: cell_binding,
                } => binding = integer(*cell_binding),
                MemoryLocationKind::Capture {
                    lexical_parent: parent,
                    binding: capture_binding,
                } => {
                    lexical_parent = integer(*parent);
                    binding = optional(*capture_binding);
                }
            }
            let value_copy_identity = match location.value_copy {
                MemoryValueCopy::BackingStore { identity } => code(identity),
                MemoryValueCopy::Unknown | MemoryValueCopy::Value | MemoryValueCopy::Reference => {
                    Value::Null
                }
            };
            self.rows.push(
                Table::MemoryLocations,
                vec![
                    integer(id),
                    integer(location.id),
                    code(MemoryLocationKindTag::of(&location.kind)),
                    base,
                    member,
                    property_key,
                    index_value,
                    constant_index,
                    index_identity,
                    lexical_parent,
                    binding,
                    code(MemoryValueCopyTag::of(&location.value_copy)),
                    value_copy_identity,
                    integer(location.source),
                    integer(location.evidence),
                ],
            );
        }
    }

    fn captures(&mut self, procedure: &'a ProcedureSemanticsParts) {
        let id = procedure.id.get();
        for (index, capture) in procedure.captures.iter().enumerate() {
            assert_eq!(capture.id.index(), index, "procedure {id} capture {index}");
            let captured = match capture.captured {
                CaptureSource::Value(value) => integer(value),
                CaptureSource::Location(location) => integer(location),
            };
            let mode_text = match &capture.mode {
                CaptureMode::LanguageDefined(text) => some(self.text(text)),
                _ => Value::Null,
            };
            self.rows.push(
                Table::Captures,
                vec![
                    integer(id),
                    integer(capture.id),
                    integer(capture.point),
                    integer(capture.callable),
                    integer(capture.target),
                    integer(capture.environment),
                    code(CaptureSourceTag::of(&capture.captured)),
                    captured,
                    integer(capture.destination),
                    code(CaptureModeTag::of(&capture.mode)),
                    mode_text,
                    integer(capture.source),
                    integer(capture.evidence),
                ],
            );
        }
    }

    fn call_sites(&mut self, procedure: &'a ProcedureSemanticsParts) {
        let id = procedure.id.get();
        for (index, call) in procedure.call_sites.iter().enumerate() {
            assert_eq!(call.id.index(), index, "procedure {id} call site {index}");
            let normal_results = if call.normal_results.is_empty() {
                Value::Null
            } else {
                json_ids(
                    call.normal_results
                        .iter()
                        .map(|value| i64::from(value.get())),
                )
            };
            let [resolution, targets] = self.resolution(id, &call.declared_targets);
            let [normal, normal_target] = continuation(call.normal_continuation);
            let [exceptional, exceptional_target] = continuation(call.exceptional_continuation);
            self.rows.push(
                Table::CallSites,
                vec![
                    integer(id),
                    integer(call.id),
                    integer(call.point),
                    code(call.invocation_mode),
                    code(call.execution_timing),
                    integer(call.callee),
                    optional(call.receiver),
                    optional(call.result),
                    optional(call.thrown),
                    normal_results,
                    resolution,
                    targets,
                    integer(call.target_evidence),
                    normal,
                    normal_target,
                    exceptional,
                    exceptional_target,
                    integer(call.source),
                    integer(call.evidence),
                ],
            );
            for (ordinal, argument) in call.arguments.iter().enumerate() {
                let [domain, domain_text] = match &argument.expansion {
                    CallArgumentExpansion::Unclassified => [Value::Null, Value::Null],
                    CallArgumentExpansion::Direct(domain)
                    | CallArgumentExpansion::Spread(domain) => self.domain(domain),
                };
                let keyword = self.optional_text(argument.keyword.as_deref());
                self.rows.push(
                    Table::CallArguments,
                    vec![
                        integer(id),
                        integer(call.id),
                        some(i64::try_from(ordinal).expect("argument ordinal fits i64")),
                        integer(argument.value),
                        code(ExpansionTag::of(&argument.expansion)),
                        domain,
                        domain_text,
                        keyword,
                    ],
                );
            }
        }
    }

    fn source_mappings(&mut self, procedure: &'a ProcedureSemanticsParts) {
        let id = procedure.id.get();
        for (index, mapping) in procedure.source_mappings.iter().enumerate() {
            assert_eq!(
                mapping.id.index(),
                index,
                "procedure {id} source mapping {index}"
            );
            let ast_node = mapping.ast_identity.map_or(Value::Null, |identity| {
                assert_eq!(
                    identity.content(),
                    self.content,
                    "procedure {id} source mapping {index} names another file content"
                );
                integer(identity.normalized_node_id())
            });
            let locator = self.locator(&mapping.locator);
            self.rows.push(
                Table::SourceMappings,
                vec![
                    integer(id),
                    integer(mapping.id),
                    some(locator),
                    code(mapping.kind),
                    ast_node,
                ],
            );
        }
    }

    fn sites(&mut self, procedure: &'a ProcedureSemanticsParts) {
        let id = procedure.id.get();
        for (ordinal, entry) in procedure.statement_entries.iter().enumerate() {
            self.rows.push(
                Table::StatementEntries,
                vec![
                    integer(id),
                    some(i64::try_from(ordinal).expect("ordinal fits i64")),
                    integer(entry.source),
                    integer(entry.evidence),
                    integer(entry.point),
                ],
            );
        }
        for (ordinal, site) in procedure.loop_sites.iter().enumerate() {
            self.rows.push(
                Table::LoopSites,
                vec![
                    integer(id),
                    some(i64::try_from(ordinal).expect("ordinal fits i64")),
                    integer(site.source),
                    integer(site.evidence),
                    integer(site.header),
                    integer(site.body),
                ],
            );
        }
    }

    fn evidence(&mut self, procedure: &'a ProcedureSemanticsParts) {
        let id = procedure.id.get();
        for (index, evidence) in procedure.evidence_rows.iter().enumerate() {
            assert_eq!(
                evidence.id.index(),
                index,
                "procedure {id} evidence {index}"
            );
            let proof_reason = match &evidence.proof {
                ProofStatus::Proven => Value::Null,
                ProofStatus::Unproven(reason) => some(self.text(reason)),
            };
            let completeness_reason = match &evidence.completeness {
                EvidenceCompleteness::Complete => Value::Null,
                EvidenceCompleteness::Partial(reason) => some(self.text(reason)),
            };
            self.rows.push(
                Table::Evidence,
                vec![
                    integer(id),
                    integer(evidence.id),
                    code(ProofTag::of(&evidence.proof)),
                    proof_reason,
                    code(CompletenessTag::of(&evidence.completeness)),
                    completeness_reason,
                    json_ids(
                        evidence
                            .sources
                            .iter()
                            .map(|source| i64::from(source.get())),
                    ),
                ],
            );
        }
    }

    fn gaps(&mut self, procedure: &'a ProcedureSemanticsParts) {
        let id = procedure.id.get();
        for (index, gap) in procedure.gaps.iter().enumerate() {
            assert_eq!(gap.id.index(), index, "procedure {id} gap {index}");
            let (subject_a, subject_b) = match gap.subject {
                SemanticGapSubject::Procedure | SemanticGapSubject::Point => {
                    (Value::Null, Value::Null)
                }
                SemanticGapSubject::Value(value) => (integer(value), Value::Null),
                SemanticGapSubject::MemoryLocation(location) => (integer(location), Value::Null),
                SemanticGapSubject::Capture(capture) => (integer(capture), Value::Null),
                SemanticGapSubject::CallSite(call) => (integer(call), Value::Null),
                SemanticGapSubject::CallContinuation { call_site, kind } => {
                    (integer(call_site), code(kind))
                }
                SemanticGapSubject::AsyncContinuation { suspend, kind } => {
                    (integer(suspend), code(kind))
                }
            };
            let impacts = gap
                .impacts
                .iter()
                .fold(0_i64, |bits, impact| bits | (1_i64 << (impact as u8)));
            let detail = self.text(&gap.detail);
            self.rows.push(
                Table::Gaps,
                vec![
                    integer(id),
                    integer(gap.id),
                    integer(gap.point),
                    code(GapSubjectTag::of(&gap.subject)),
                    subject_a,
                    subject_b,
                    code(gap.capability),
                    some(impacts),
                    code(gap.kind),
                    gap.budget
                        .map_or(Value::Null, |budget| code(budget.dimension())),
                    gap.budget.map_or(Value::Null, |budget| {
                        some(i64::try_from(budget.limit()).expect("budget limit fits i64"))
                    }),
                    gap.budget.map_or(Value::Null, |budget| {
                        some(i64::try_from(budget.attempted()).expect("budget attempt fits i64"))
                    }),
                    code(gap.discharge),
                    some(detail),
                    integer(gap.source),
                    integer(gap.evidence),
                ],
            );
        }
    }

    fn blocks_and_points(&mut self, procedure: &'a ProcedureSemanticsParts) {
        let id = procedure.id.get();
        for (index, block) in procedure.blocks.iter().enumerate() {
            assert_eq!(block.id.index(), index, "procedure {id} block {index}");
            self.rows.push(
                Table::Blocks,
                vec![
                    integer(id),
                    integer(block.id),
                    json_ids(block.points.iter().map(|point| i64::from(point.get()))),
                    integer(block.source),
                    integer(block.evidence),
                ],
            );
        }
        for (index, point) in procedure.points.iter().enumerate() {
            assert_eq!(point.id.index(), index, "procedure {id} point {index}");
            self.rows.push(
                Table::Points,
                vec![
                    integer(id),
                    integer(point.id),
                    integer(point.block),
                    integer(point.source),
                    integer(point.evidence),
                ],
            );
            for (ordinal, event) in point.events.iter().enumerate() {
                let key = [
                    integer(id),
                    integer(point.id),
                    some(i64::try_from(ordinal).expect("event ordinal fits i64")),
                ];
                let cells = self.event(&key, &event.effect);
                self.rows.push(
                    Table::Events,
                    vec![
                        key[0].clone(),
                        key[1].clone(),
                        key[2].clone(),
                        code(EffectTag::of(&event.effect)),
                        cells.sub_kind.map_or(Value::Null, some),
                        optional(cells.value_a),
                        optional(cells.value_b),
                        optional(cells.value_c),
                        optional(cells.location),
                        optional(cells.allocation),
                        optional(cells.call_site),
                        optional(cells.capture),
                        optional(cells.gap),
                        cells.locator.map_or(Value::Null, some),
                        optional(cells.suspend_point),
                        integer(event.source),
                        integer(event.evidence),
                    ],
                );
            }
        }
    }

    /// The event's own columns; payload rows go to the side tables under
    /// `key` (procedure, point, ordinal).
    fn event(&mut self, key: &[Value; 3], effect: &'a SemanticEffect) -> EventCells {
        let procedure = match key[0] {
            Value::Integer(procedure) => u32::try_from(procedure).expect("procedure id fits u32"),
            _ => unreachable!("the event key starts with the procedure id"),
        };
        let side = |rest: Vec<Value>| {
            let mut row = key.to_vec();
            row.extend(rest);
            row
        };
        match effect {
            SemanticEffect::Entry
            | SemanticEffect::NormalExit
            | SemanticEffect::ExceptionalExit => EventCells::default(),
            SemanticEffect::Assignment { target, value } => EventCells {
                value_a: Some(target.get()),
                value_b: Some(value.get()),
                ..EventCells::default()
            },
            SemanticEffect::AggregateInitializer {
                aggregate,
                selector,
                value,
            } => EventCells {
                value_a: Some(aggregate.get()),
                value_b: Some(value.get()),
                locator: Some(self.locator(selector)),
                ..EventCells::default()
            },
            SemanticEffect::ValueFlow {
                kind,
                source,
                target,
            } => {
                match kind {
                    ValueFlowKind::Transfer(transfer) => {
                        let detail = match transfer.kind {
                            TransferKind::Move { invalidation } => code(invalidation),
                            TransferKind::Conversion { preservation } => code(preservation),
                            TransferKind::Copy
                            | TransferKind::AggregateCopy
                            | TransferKind::Boxing
                            | TransferKind::Unboxing => Value::Null,
                        };
                        let (call_site, digest) = match transfer.operation {
                            TransferOperation::CallSite(call) => (integer(call), Value::Null),
                            TransferOperation::CallArgumentConversion(digest)
                            | TransferOperation::ValueCarrierAdaptation(digest) => {
                                (Value::Null, Value::Blob(digest.as_bytes().to_vec()))
                            }
                            TransferOperation::None | TransferOperation::Unknown => {
                                (Value::Null, Value::Null)
                            }
                        };
                        self.rows.push(
                            Table::EventTransfers,
                            side(vec![
                                code(TransferKindTag::of(&transfer.kind)),
                                detail,
                                code(TransferOperationTag::of(&transfer.operation)),
                                call_site,
                                digest,
                            ]),
                        );
                    }
                    ValueFlowKind::BackingStore { offset } => {
                        let [offset_kind, magnitude, offset_value] = backing_store_offset(*offset);
                        self.rows.push(
                            Table::EventOffsets,
                            side(vec![
                                offset_kind,
                                magnitude,
                                offset_value,
                                Value::Null,
                                Value::Null,
                                Value::Null,
                            ]),
                        );
                    }
                    ValueFlowKind::BackingStoreAlternative { offset, allocation } => {
                        let [offset_kind, magnitude, offset_value] = backing_store_offset(*offset);
                        self.rows.push(
                            Table::EventOffsets,
                            side(vec![
                                offset_kind,
                                magnitude,
                                offset_value,
                                Value::Null,
                                integer(*allocation),
                                Value::Null,
                            ]),
                        );
                    }
                    ValueFlowKind::IntegerOffset { offset } => {
                        self.rows.push(
                            Table::EventOffsets,
                            side(vec![
                                Value::Null,
                                decimal(offset.magnitude()),
                                Value::Null,
                                flag(offset.negative()),
                                Value::Null,
                                Value::Null,
                            ]),
                        );
                    }
                    ValueFlowKind::IndexedReturn { ordinal } => {
                        self.rows.push(
                            Table::EventOffsets,
                            side(vec![
                                Value::Null,
                                Value::Null,
                                Value::Null,
                                Value::Null,
                                Value::Null,
                                integer(*ordinal),
                            ]),
                        );
                    }
                    ValueFlowKind::Local
                    | ValueFlowKind::Parameter
                    | ValueFlowKind::Receiver
                    | ValueFlowKind::Return
                    | ValueFlowKind::ReferenceBoxing
                    | ValueFlowKind::ReferenceUnboxing
                    | ValueFlowKind::LanguageDefined => {}
                }
                EventCells {
                    sub_kind: Some(ValueFlowKindTag::of(kind).code()),
                    value_a: Some(source.get()),
                    value_b: Some(target.get()),
                    ..EventCells::default()
                }
            }
            SemanticEffect::ValueUse { kind, value } => EventCells {
                sub_kind: Some(kind.code()),
                value_a: Some(value.get()),
                ..EventCells::default()
            },
            SemanticEffect::Allocation { allocation } => EventCells {
                allocation: Some(allocation.get()),
                ..EventCells::default()
            },
            SemanticEffect::MemoryLoad {
                kind,
                location,
                result,
            } => EventCells {
                sub_kind: Some(kind.code()),
                location: Some(location.get()),
                value_a: Some(result.get()),
                ..EventCells::default()
            },
            SemanticEffect::MemoryStore {
                kind,
                location,
                value,
            } => EventCells {
                sub_kind: Some(kind.code()),
                location: Some(location.get()),
                value_a: Some(value.get()),
                ..EventCells::default()
            },
            SemanticEffect::Synchronization {
                operation,
                subject,
                payload,
            } => {
                if let Some(payload) = payload {
                    let (value, copy_kind, copy_identity) = match payload {
                        SynchronizationPayload::Send { value, copy } => {
                            let identity = match copy {
                                SynchronizationPayloadCopy::BackingStore { identity } => {
                                    code(*identity)
                                }
                                SynchronizationPayloadCopy::Unknown
                                | SynchronizationPayloadCopy::Reference => Value::Null,
                            };
                            (
                                integer(*value),
                                code(SynchronizationPayloadCopyTag::of(copy)),
                                identity,
                            )
                        }
                        SynchronizationPayload::Receive { result } => {
                            (integer(*result), Value::Null, Value::Null)
                        }
                    };
                    self.rows.push(
                        Table::EventSynchronizations,
                        side(vec![
                            code(SynchronizationPayloadTag::of(payload)),
                            value,
                            copy_kind,
                            copy_identity,
                        ]),
                    );
                }
                EventCells {
                    sub_kind: Some(operation.code()),
                    value_a: Some(subject.get()),
                    ..EventCells::default()
                }
            }
            SemanticEffect::CallableCreation { result, callable }
            | SemanticEffect::CallableReference { result, callable } => {
                let [resolution, targets] = self.resolution(procedure, &callable.targets);
                self.rows.push(
                    Table::EventCallables,
                    side(vec![resolution, targets, integer(callable.target_evidence)]),
                );
                let qualifier = match callable.kind {
                    CallableReferenceKind::ModuleQualified { qualifier }
                    | CallableReferenceKind::TypeQualifiedMethod { qualifier } => {
                        Some(qualifier.get())
                    }
                    CallableReferenceKind::Lambda
                    | CallableReferenceKind::Function
                    | CallableReferenceKind::BoundMethod
                    | CallableReferenceKind::UnboundMethod
                    | CallableReferenceKind::StaticMethod
                    | CallableReferenceKind::Constructor => None,
                };
                EventCells {
                    sub_kind: Some(CallableReferenceKindTag::of(&callable.kind).code()),
                    value_a: Some(result.get()),
                    value_b: qualifier,
                    value_c: callable.bound_receiver.map(|value| value.get()),
                    allocation: callable.environment.map(|allocation| allocation.get()),
                    ..EventCells::default()
                }
            }
            SemanticEffect::CaptureBind { capture } => EventCells {
                capture: Some(capture.get()),
                ..EventCells::default()
            },
            SemanticEffect::Invoke { call_site } => EventCells {
                call_site: Some(call_site.get()),
                ..EventCells::default()
            },
            SemanticEffect::CallContinuation { call_site, kind } => EventCells {
                call_site: Some(call_site.get()),
                sub_kind: Some(kind.code()),
                ..EventCells::default()
            },
            SemanticEffect::ProcedureReturn { value } | SemanticEffect::Throw { value } => {
                EventCells {
                    value_a: value.map(|value| value.get()),
                    ..EventCells::default()
                }
            }
            SemanticEffect::AsyncSuspend {
                awaited,
                normal_resume,
                exceptional_resume,
            } => {
                let [normal, normal_target] = continuation(*normal_resume);
                let [exceptional, exceptional_target] = continuation(*exceptional_resume);
                self.rows.push(
                    Table::EventAsyncSuspends,
                    side(vec![normal, normal_target, exceptional, exceptional_target]),
                );
                EventCells {
                    value_a: awaited.map(|value| value.get()),
                    ..EventCells::default()
                }
            }
            SemanticEffect::AsyncResume {
                suspend,
                kind,
                result,
            } => EventCells {
                suspend_point: Some(suspend.get()),
                sub_kind: Some(kind.code()),
                value_a: result.map(|value| value.get()),
                ..EventCells::default()
            },
            SemanticEffect::Gap { gap } => EventCells {
                gap: Some(gap.get()),
                ..EventCells::default()
            },
        }
    }

    fn control_edges(&mut self, procedure: &'a ProcedureSemanticsParts) {
        let id = procedure.id.get();
        for (ordinal, edge) in procedure.control_edges.iter().enumerate() {
            self.rows.push(
                Table::ControlEdges,
                vec![
                    integer(id),
                    some(i64::try_from(ordinal).expect("edge ordinal fits i64")),
                    integer(edge.source_point),
                    integer(edge.target_point),
                    code(edge.kind),
                    integer(edge.source),
                    integer(edge.evidence),
                ],
            );
        }
    }

    fn guard_facts(&mut self, procedure: &'a ProcedureSemanticsParts) {
        let id = procedure.id.get();
        for (index, guard) in procedure.guard_facts.iter().enumerate() {
            assert_eq!(guard.id.index(), index, "procedure {id} guard {index}");
            let mut guard_flag = Value::Null;
            let mut relation = Value::Null;
            let mut constant = Value::Null;
            let mut operand_a = Value::Null;
            let mut operand_b = Value::Null;
            let mut digest = Value::Null;
            match guard.predicate {
                GuardPredicate::ConstantBoolean { value } => guard_flag = flag(value),
                GuardPredicate::NullComparison { null_on_true } => guard_flag = flag(null_on_true),
                GuardPredicate::ConstantEquality {
                    negated,
                    constant: equal,
                } => {
                    guard_flag = flag(negated);
                    constant = integer(equal);
                }
                GuardPredicate::OrderedIntegerComparison {
                    relation: ordering,
                    constant: bound,
                }
                | GuardPredicate::OrderedFloatComparison {
                    relation: ordering,
                    constant: bound,
                } => {
                    relation = code(ordering);
                    constant = integer(bound);
                }
                GuardPredicate::NanComparison { nan_on_true } => guard_flag = flag(nan_on_true),
                GuardPredicate::InstanceOf { value, classes } => {
                    operand_a = integer(value);
                    operand_b = integer(classes);
                }
                GuardPredicate::ExactClass {
                    value,
                    classes,
                    exact_on_true,
                } => {
                    operand_a = integer(value);
                    operand_b = integer(classes);
                    guard_flag = flag(exact_on_true);
                }
                GuardPredicate::HasMember { value, member } => {
                    operand_a = integer(value);
                    operand_b = integer(member);
                }
                GuardPredicate::Truthy { value } => operand_a = integer(value),
                GuardPredicate::Opaque { digest: condition } => {
                    digest = some(i64::from_ne_bytes(condition.get().to_ne_bytes()));
                }
            }
            let [true_target, true_kind] = arm(guard.true_arm);
            let [false_target, false_kind] = arm(guard.false_arm);
            self.rows.push(
                Table::GuardFacts,
                vec![
                    integer(id),
                    integer(guard.id),
                    integer(guard.point),
                    optional(guard.subject),
                    code(GuardPredicateTag::of(&guard.predicate)),
                    guard_flag,
                    relation,
                    constant,
                    operand_a,
                    operand_b,
                    digest,
                    true_target,
                    true_kind,
                    false_target,
                    false_kind,
                    integer(guard.source),
                    integer(guard.evidence),
                ],
            );
        }
    }

    fn switch_facts(&mut self, procedure: &'a ProcedureSemanticsParts) {
        let id = procedure.id.get();
        for (index, switch) in procedure.switch_facts.iter().enumerate() {
            assert_eq!(switch.id.index(), index, "procedure {id} switch {index}");
            let [default_source, default_target, default_kind] = match switch.default_edge {
                Some(SwitchEdgeParts { source_point, arm }) => [
                    integer(source_point),
                    integer(arm.target_point),
                    code(arm.kind),
                ],
                None => [Value::Null, Value::Null, Value::Null],
            };
            self.rows.push(
                Table::SwitchFacts,
                vec![
                    integer(id),
                    integer(switch.id),
                    code(switch.kind),
                    integer(switch.point),
                    optional(switch.selector),
                    code(switch.selector_domain),
                    flag(switch.default_present),
                    default_source,
                    default_target,
                    default_kind,
                    integer(switch.source),
                    integer(switch.evidence),
                ],
            );
            for (ordinal, case) in switch.cases.iter().enumerate() {
                self.rows.push(
                    Table::SwitchCases,
                    vec![
                        integer(id),
                        integer(switch.id),
                        some(i64::try_from(ordinal).expect("case ordinal fits i64")),
                        integer(case.value),
                        integer(case.edge.source_point),
                        integer(case.edge.arm.target_point),
                        code(case.edge.arm.kind),
                    ],
                );
            }
        }
    }

    fn lifecycle(&mut self, procedure: &'a ProcedureSemanticsParts) {
        let id = procedure.id.get();
        for (ordinal, drop) in procedure.drops.iter().enumerate() {
            let [place_kind, place_locator, place_location] = self.place(&drop.place);
            let [resolution, targets] = match &drop.behavior {
                DropBehavior::Trivial => [Value::Null, Value::Null],
                DropBehavior::Destructor(resolution) => self.resolution(id, resolution),
            };
            self.rows.push(
                Table::Drops,
                vec![
                    integer(id),
                    some(i64::try_from(ordinal).expect("ordinal fits i64")),
                    place_kind,
                    place_locator,
                    place_location,
                    integer(drop.point),
                    code(DropBehaviorTag::of(&drop.behavior)),
                    resolution,
                    targets,
                    integer(drop.source),
                    integer(drop.evidence),
                ],
            );
        }
        for (ordinal, move_out) in procedure.move_outs.iter().enumerate() {
            let [place_kind, place_locator, place_location] = self.place(&move_out.place);
            self.rows.push(
                Table::MoveOuts,
                vec![
                    integer(id),
                    some(i64::try_from(ordinal).expect("ordinal fits i64")),
                    place_kind,
                    place_locator,
                    place_location,
                    integer(move_out.point),
                    integer(move_out.source_value),
                    integer(move_out.target_value),
                    code(move_out.state_after),
                    integer(move_out.source),
                    integer(move_out.evidence),
                ],
            );
        }
        for (ordinal, end) in procedure.scope_ends.iter().enumerate() {
            let [place_kind, place_locator, place_location] = self.place(&end.place);
            let [at_point, edge_source, edge_target, edge_kind] = match end.at {
                ScopeEndAt::Point(point) => [integer(point), Value::Null, Value::Null, Value::Null],
                ScopeEndAt::Edge {
                    source_point,
                    target_point,
                    kind,
                } => [
                    Value::Null,
                    integer(source_point),
                    integer(target_point),
                    code(kind),
                ],
            };
            self.rows.push(
                Table::ScopeEnds,
                vec![
                    integer(id),
                    some(i64::try_from(ordinal).expect("ordinal fits i64")),
                    place_kind,
                    place_locator,
                    place_location,
                    code(ScopeEndAtTag::of(&end.at)),
                    at_point,
                    edge_source,
                    edge_target,
                    edge_kind,
                    integer(end.source),
                    integer(end.evidence),
                ],
            );
        }
    }

    fn pointers(&mut self, procedure: &'a ProcedureSemanticsParts) {
        let id = procedure.id.get();
        for (index, origin) in procedure.pointer_origins.iter().enumerate() {
            assert_eq!(
                origin.id.index(),
                index,
                "procedure {id} pointer origin {index}"
            );
            let [place_kind, place_locator, place_location, allocation] = match &origin.kind {
                PointerOriginKind::StackPlace { place } => {
                    let [kind, locator, location] = self.place(place);
                    [kind, locator, location, Value::Null]
                }
                PointerOriginKind::Allocation { allocation } => {
                    [Value::Null, Value::Null, Value::Null, integer(*allocation)]
                }
            };
            self.rows.push(
                Table::PointerOrigins,
                vec![
                    integer(id),
                    integer(origin.id),
                    integer(origin.point),
                    code(PointerOriginKindTag::of(&origin.kind)),
                    place_kind,
                    place_locator,
                    place_location,
                    allocation,
                    origin.byte_extent.map_or(Value::Null, decimal),
                    integer(origin.source),
                    integer(origin.evidence),
                ],
            );
        }
        for (ordinal, alias) in procedure.pointer_aliases.iter().enumerate() {
            let [exact, value, minimum, maximum] = match alias.byte_offset {
                PointerByteOffset::Exact(offset) => {
                    [decimal(offset), Value::Null, Value::Null, Value::Null]
                }
                PointerByteOffset::Value(offset) => {
                    [Value::Null, integer(offset), Value::Null, Value::Null]
                }
                PointerByteOffset::Range { minimum, maximum } => {
                    [Value::Null, Value::Null, decimal(minimum), decimal(maximum)]
                }
                PointerByteOffset::Unknown => [Value::Null, Value::Null, Value::Null, Value::Null],
            };
            self.rows.push(
                Table::PointerAliases,
                vec![
                    integer(id),
                    some(i64::try_from(ordinal).expect("ordinal fits i64")),
                    integer(alias.point),
                    integer(alias.pointer),
                    integer(alias.origin),
                    code(PointerByteOffsetTag::of(&alias.byte_offset)),
                    exact,
                    value,
                    minimum,
                    maximum,
                    code(alias.strength),
                    integer(alias.source),
                    integer(alias.evidence),
                ],
            );
        }
        for (ordinal, access) in procedure.pointer_accesses.iter().enumerate() {
            let [exact, value, multiplier] = match access.width {
                PointerAccessWidth::Exact(width) => [decimal(width), Value::Null, Value::Null],
                PointerAccessWidth::ValueTimes { value, multiplier } => {
                    [Value::Null, integer(value), decimal(multiplier)]
                }
                PointerAccessWidth::Unknown => [Value::Null, Value::Null, Value::Null],
            };
            self.rows.push(
                Table::PointerAccesses,
                vec![
                    integer(id),
                    some(i64::try_from(ordinal).expect("ordinal fits i64")),
                    integer(access.point),
                    integer(access.pointer),
                    code(access.kind),
                    code(PointerAccessWidthTag::of(&access.width)),
                    exact,
                    value,
                    multiplier,
                    integer(access.source),
                    integer(access.evidence),
                ],
            );
        }
        for (ordinal, invalidation) in procedure.pointer_invalidations.iter().enumerate() {
            let [value, origin] = match invalidation.target {
                PointerInvalidationTarget::Pointer(value) => [integer(value), Value::Null],
                PointerInvalidationTarget::Origin(origin) => [Value::Null, integer(origin)],
            };
            self.rows.push(
                Table::PointerInvalidations,
                vec![
                    integer(id),
                    some(i64::try_from(ordinal).expect("ordinal fits i64")),
                    integer(invalidation.point),
                    code(PointerInvalidationTargetTag::of(&invalidation.target)),
                    value,
                    origin,
                    code(invalidation.cause),
                    code(invalidation.strength),
                    integer(invalidation.source),
                    integer(invalidation.evidence),
                ],
            );
        }
        for (ordinal, fact) in procedure.incomplete_facts.iter().enumerate() {
            let [place_kind, place_locator, place_location, value, origin] = match &fact.subject {
                SemanticIncompleteSubject::Procedure => [
                    Value::Null,
                    Value::Null,
                    Value::Null,
                    Value::Null,
                    Value::Null,
                ],
                SemanticIncompleteSubject::Place(place) => {
                    let [kind, locator, location] = self.place(place);
                    [kind, locator, location, Value::Null, Value::Null]
                }
                SemanticIncompleteSubject::Value(value) => [
                    Value::Null,
                    Value::Null,
                    Value::Null,
                    integer(*value),
                    Value::Null,
                ],
                SemanticIncompleteSubject::PointerOrigin(origin) => [
                    Value::Null,
                    Value::Null,
                    Value::Null,
                    Value::Null,
                    integer(*origin),
                ],
            };
            let reason = match fact.reason {
                SemanticIncompleteReason::Lifecycle(reason) => code(reason),
                SemanticIncompleteReason::Pointer(reason) => code(reason),
            };
            self.rows.push(
                Table::IncompleteFacts,
                vec![
                    integer(id),
                    some(i64::try_from(ordinal).expect("ordinal fits i64")),
                    integer(fact.point),
                    code(IncompleteSubjectTag::of(&fact.subject)),
                    place_kind,
                    place_locator,
                    place_location,
                    value,
                    origin,
                    code(IncompleteReasonTag::of(&fact.reason)),
                    reason,
                    integer(fact.source),
                    integer(fact.evidence),
                ],
            );
        }
    }

    fn receiver_type_facts(&mut self, procedure: &'a ProcedureSemanticsParts) {
        let id = procedure.id.get();
        for fact in &procedure.receiver_type_facts {
            let member = self.text(&fact.member);
            let segments = fact
                .receiver_type
                .iter()
                .map(|segment| self.text(segment))
                .collect::<Vec<_>>();
            self.rows.push(
                Table::ReceiverTypeFacts,
                vec![
                    integer(id),
                    integer(fact.call_site),
                    some(member),
                    json_ids(segments.into_iter()),
                ],
            );
        }
    }
}

impl<'a> Encoder<'a> {
    /// One procedure's ports, flows and head. Ports come first in id order,
    /// so a heap port's root is always a row already written.
    fn partial_flows(&mut self, procedure: u32, flows: &'a ProcedurePartialFlows) {
        let port_ids = flows
            .ports
            .iter()
            .enumerate()
            .map(|(index, port)| (port, index))
            .collect::<HashMap<&PartialFlowPort, usize>>();
        for (index, port) in flows.ports.iter().enumerate() {
            let [a, b, root, selectors, tail] = self.port_cells(port, &port_ids, index);
            self.rows.push(
                Table::PartialPorts,
                vec![
                    integer(procedure),
                    some(i64::try_from(index).expect("port index fits i64")),
                    code(PartialPortTag::of(port)),
                    a,
                    b,
                    root,
                    selectors,
                    tail,
                ],
            );
        }
        let gaps = flows
            .discharged_gaps
            .iter()
            .map(|gap| i64::from(gap.get()))
            .collect::<Vec<_>>();
        let detail = self.optional_text(flows.detail.as_deref());
        self.rows.push(
            Table::PartialFlowHeads,
            vec![
                integer(procedure),
                code(flows.outcome),
                detail,
                flag(flows.open),
                flag(flows.relations_complete),
                some(i64::try_from(flows.ports.len()).expect("port count fits i64")),
                some(i64::try_from(flows.flows.len()).expect("flow count fits i64")),
                json_ids(gaps.into_iter()),
            ],
        );
        for flow in &flows.flows {
            let crossed = flow
                .crossed
                .iter()
                .map(|set| set.iter().map(|call| call.get()).collect::<Vec<_>>())
                .collect::<Vec<_>>();
            self.rows.push(
                Table::PartialFlows,
                vec![
                    integer(procedure),
                    some(i64::from(flow.from.get())),
                    some(i64::from(flow.to.get())),
                    flag(flow.uncertain),
                    Value::Text(serde_json::to_string(&crossed).expect("integer arrays serialize")),
                ],
            );
        }
    }

    /// The `a`, `b`, `root`, `selectors` and `tail` cells of one port.
    fn port_cells(
        &mut self,
        port: &'a PartialFlowPort,
        port_ids: &HashMap<&PartialFlowPort, usize>,
        index: usize,
    ) -> [Value; 5] {
        let nothing = || {
            [
                Value::Null,
                Value::Null,
                Value::Null,
                Value::Null,
                Value::Null,
            ]
        };
        match port {
            PartialFlowPort::Receiver
            | PartialFlowPort::NormalReturn
            | PartialFlowPort::ExceptionalReturn => nothing(),
            PartialFlowPort::Parameter { ordinal }
            | PartialFlowPort::IndexedNormalReturn { ordinal } => {
                let [_, b, root, selectors, tail] = nothing();
                [integer(*ordinal), b, root, selectors, tail]
            }
            PartialFlowPort::CallReceiver { call } | PartialFlowPort::CallThrown { call } => {
                let [_, b, root, selectors, tail] = nothing();
                [integer(call.get()), b, root, selectors, tail]
            }
            PartialFlowPort::CallArgument { call, ordinal } => {
                let [_, _, root, selectors, tail] = nothing();
                [
                    integer(call.get()),
                    integer(*ordinal),
                    root,
                    selectors,
                    tail,
                ]
            }
            PartialFlowPort::CallResult { call, ordinal } => {
                let [_, _, root, selectors, tail] = nothing();
                [
                    integer(call.get()),
                    optional(*ordinal),
                    root,
                    selectors,
                    tail,
                ]
            }
            PartialFlowPort::Capture { slot } => {
                let [_, b, root, selectors, tail] = nothing();
                [integer(slot.get()), b, root, selectors, tail]
            }
            PartialFlowPort::CaptureOut {
                target,
                destination,
            } => {
                let [_, _, root, selectors, tail] = nothing();
                [
                    integer(target.get()),
                    integer(destination.get()),
                    root,
                    selectors,
                    tail,
                ]
            }
            PartialFlowPort::Heap {
                root,
                selectors,
                tail,
            } => {
                let root_index = *port_ids
                    .get(root.as_ref())
                    .expect("a heap port's root is one of the procedure's ports");
                assert!(
                    root_index < index,
                    "a heap port's root is interned before the heap port"
                );
                let [a, b, _, _, _] = nothing();
                [
                    a,
                    b,
                    some(i64::try_from(root_index).expect("port index fits i64")),
                    self.heap_selectors(selectors),
                    code(*tail),
                ]
            }
        }
    }

    /// A JSONB array of `[kind, operand]` pairs in selector order.
    fn heap_selectors(&mut self, selectors: &'a [HeapSelector]) -> Value {
        let mut tokens = Vec::<(i64, Option<i64>)>::with_capacity(selectors.len());
        for selector in selectors {
            let kind = HeapSelectorTag::of(selector).code();
            let operand = match selector {
                HeapSelector::Field(locator) => Some(self.locator(locator)),
                HeapSelector::Property(text) | HeapSelector::ConstantIndex(text) => {
                    Some(self.text(text))
                }
                HeapSelector::ExactIndex(value) => Some(i64::from(value.get())),
                HeapSelector::AnyIndex => None,
            };
            tokens.push((kind, operand));
        }
        Value::Text(serde_json::to_string(&tokens).expect("selector tokens serialize"))
    }
}

fn backing_store_offset(offset: BackingStoreOffset) -> [Value; 3] {
    let tag = code(BackingStoreOffsetTag::of(&offset));
    match offset {
        BackingStoreOffset::Zero => [tag, Value::Null, Value::Null],
        BackingStoreOffset::Constant(magnitude) => [tag, decimal(magnitude), Value::Null],
        BackingStoreOffset::Value(value) => [tag, Value::Null, integer(value)],
    }
}
