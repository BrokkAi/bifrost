-- Per-blob semantic IR rows.
--
-- A blob that its adapter lowers at parse time stores the lowered semantic
-- IR here, one row per IR element, so a reader rebuilds the artifact without
-- re-lowering the file. The rows depend only on the blob's bytes and the
-- producer epoch (derivation contract, kind 1).
--
-- Conventions shared by every table below:
-- * An enumeration is the zero-based position of the variant in its Rust
--   declaration, bounded by a CHECK.
-- * A Boolean is 0 or 1.
-- * A u128 or i128 magnitude is decimal TEXT; a negative i128 has a leading
--   minus sign.
-- * A u64 bit pattern is the INTEGER two's-complement reinterpretation.
-- * Every string is interned per blob in semantic_ir_texts; a "text id"
--   column holds its text_id.
-- * A "locator id" is a semantic_ir_locators.locator of the same blob; a
--   "declaration id" is a semantic_ir_declaration_segments.declaration.
-- * "procedure" is the artifact-local procedure id. Every other id column
--   (value, point, block, call site, allocation, memory location, capture,
--   gap, source mapping, evidence, guard, switch, pointer origin) is local
--   to the row's procedure.
-- * A source anchor is the seven columns start_byte, start_line,
--   start_column, end_byte, end_line, end_column, occurrence.
-- * `source` and `evidence` are the row's SourceMappingId and EvidenceId.

-- The active producer epoch per storage language, mirroring
-- resolution_producer_epochs. A language has a row only when its adapter
-- lowers at parse time.
CREATE TABLE semantic_ir_producer_epochs(
  lang           TEXT NOT NULL,
  producer_epoch TEXT NOT NULL CHECK(length(producer_epoch) > 0),
  PRIMARY KEY(lang)
) WITHOUT ROWID, STRICT;

-- The head: one row per blob prepared under a parse-time lowerer. A reader
-- may use a blob's rows only when publication_state = 'complete' and
-- producer_epoch equals the language's semantic_ir_producer_epochs row.
-- outcome: 0 complete, 1 exceeded_budget, 2 unsupported, 3 incomplete,
-- 4 error, 5 panicked. Only outcome 0 has child rows. detail holds the
-- capability label, the outcome label, the error or the panic message for
-- outcomes 2 to 5. budget_* hold the exceeded budget for outcome 1.
-- go_predeclared_builtins: JSONB array of builtin names as strings, sorted
-- and without duplicates; the decoder restores them onto procedure 0.
CREATE TABLE semantic_ir_publications(
  blob_id                 INTEGER NOT NULL PRIMARY KEY
    REFERENCES blobs(id) ON DELETE CASCADE,
  lang                    TEXT NOT NULL,
  producer_epoch          TEXT NOT NULL CHECK(length(producer_epoch) > 0),
  content_digest          BLOB NOT NULL CHECK(length(content_digest) = 32),
  source_bytes            INTEGER NOT NULL,
  outcome                 INTEGER NOT NULL CHECK(outcome BETWEEN 0 AND 5),
  detail                  TEXT,
  budget_dimension        INTEGER CHECK(budget_dimension BETWEEN 0 AND 15),
  budget_limit            INTEGER,
  budget_attempted        INTEGER,
  procedure_count         INTEGER NOT NULL,
  logical_rows            INTEGER NOT NULL,
  payload_bytes           INTEGER NOT NULL,
  go_predeclared_builtins BLOB NOT NULL CHECK(json_valid(go_predeclared_builtins, 8)),
  publication_state       TEXT NOT NULL CHECK(publication_state IN ('building', 'complete'))
) WITHOUT ROWID, STRICT;

-- One interned string per text id.
CREATE TABLE semantic_ir_texts(
  blob_id INTEGER NOT NULL,
  text_id INTEGER NOT NULL,
  text    TEXT NOT NULL,
  PRIMARY KEY(blob_id, text_id),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

-- One segment of one interned DeclarationLocator. kind follows
-- DeclarationSegmentKind; name is a text id, NULL for an anonymous segment.
CREATE TABLE semantic_ir_declaration_segments(
  blob_id         INTEGER NOT NULL,
  declaration     INTEGER NOT NULL,
  ordinal         INTEGER NOT NULL,
  kind            INTEGER NOT NULL CHECK(kind BETWEEN 0 AND 10),
  name            INTEGER,
  start_byte      INTEGER NOT NULL,
  start_line      INTEGER NOT NULL,
  start_column    INTEGER NOT NULL,
  end_byte        INTEGER NOT NULL,
  end_line        INTEGER NOT NULL,
  end_column      INTEGER NOT NULL,
  occurrence      INTEGER NOT NULL,
  sibling_ordinal INTEGER NOT NULL,
  PRIMARY KEY(blob_id, declaration, ordinal),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

-- One interned SemanticLocator without mount or language, which the reader
-- takes from the mount it serves. path is NULL for the blob's own path and
-- otherwise the text id of another workspace-relative path in the same
-- mount (the Rust lowerer's canonical field-member locators use one). role
-- follows SemanticRole.
CREATE TABLE semantic_ir_locators(
  blob_id      INTEGER NOT NULL,
  locator      INTEGER NOT NULL,
  path         INTEGER,
  declaration  INTEGER NOT NULL,
  role         INTEGER NOT NULL CHECK(role BETWEEN 0 AND 11),
  start_byte   INTEGER NOT NULL,
  start_line   INTEGER NOT NULL,
  start_column INTEGER NOT NULL,
  end_byte     INTEGER NOT NULL,
  end_line     INTEGER NOT NULL,
  end_column   INTEGER NOT NULL,
  occurrence   INTEGER NOT NULL,
  PRIMARY KEY(blob_id, locator),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

-- One procedure. kind follows ProcedureKind; invocation, call_boundary,
-- receiver_binding and construction_return follow their property enums;
-- dispatch_extensibility follows DispatchExtensibility. Entry and exit
-- points are derived when the artifact is built.
CREATE TABLE semantic_ir_procedures(
  blob_id                INTEGER NOT NULL,
  procedure              INTEGER NOT NULL,
  locator                INTEGER NOT NULL,
  lexical_parent         INTEGER,
  kind                   INTEGER NOT NULL CHECK(kind BETWEEN 0 AND 8),
  is_async               INTEGER NOT NULL CHECK(is_async IN (0, 1)),
  is_generator           INTEGER NOT NULL CHECK(is_generator IN (0, 1)),
  is_static              INTEGER NOT NULL CHECK(is_static IN (0, 1)),
  is_synthetic           INTEGER NOT NULL CHECK(is_synthetic IN (0, 1)),
  invocation             INTEGER NOT NULL CHECK(invocation BETWEEN 0 AND 1),
  dispatch_extensibility INTEGER NOT NULL CHECK(dispatch_extensibility BETWEEN 0 AND 1),
  call_boundary          INTEGER NOT NULL CHECK(call_boundary BETWEEN 0 AND 1),
  receiver_binding       INTEGER NOT NULL CHECK(receiver_binding BETWEEN 0 AND 1),
  construction_return    INTEGER NOT NULL CHECK(construction_return BETWEEN 0 AND 1),
  source                 INTEGER NOT NULL,
  evidence               INTEGER NOT NULL,
  PRIMARY KEY(blob_id, procedure),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

-- One value. kind follows SemanticValueKind. Parameter uses ordinal,
-- multiplicity (0 one, 1 rest), rest_domain (ArgumentDomain, with
-- rest_domain_text for LanguageDefined), name and passing_mode
-- (FormalParameterPassingMode). DefaultArgument uses ordinal. Receiver and
-- Boolean use flag. UnsignedInteger and SignedInteger use magnitude.
-- FloatingPoint uses float_bits. ConstantString and LanguageDefined use
-- text. Text columns hold text ids except magnitude.
CREATE TABLE semantic_ir_values(
  blob_id          INTEGER NOT NULL,
  procedure        INTEGER NOT NULL,
  value            INTEGER NOT NULL,
  kind             INTEGER NOT NULL CHECK(kind BETWEEN 0 AND 17),
  ordinal          INTEGER,
  multiplicity     INTEGER CHECK(multiplicity BETWEEN 0 AND 1),
  rest_domain      INTEGER CHECK(rest_domain BETWEEN 0 AND 3),
  rest_domain_text INTEGER,
  name             INTEGER,
  passing_mode     INTEGER CHECK(passing_mode BETWEEN 0 AND 2),
  flag             INTEGER CHECK(flag IN (0, 1)),
  magnitude        TEXT,
  float_bits       INTEGER,
  text             INTEGER,
  source           INTEGER NOT NULL,
  evidence         INTEGER NOT NULL,
  PRIMARY KEY(blob_id, procedure, value),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

-- One allocation site. kind follows AllocationKind; kind_text is the text
-- id of a LanguageDefined kind.
CREATE TABLE semantic_ir_allocations(
  blob_id    INTEGER NOT NULL,
  procedure  INTEGER NOT NULL,
  allocation INTEGER NOT NULL,
  point      INTEGER NOT NULL,
  result     INTEGER NOT NULL,
  kind       INTEGER NOT NULL CHECK(kind BETWEEN 0 AND 6),
  kind_text  INTEGER,
  source     INTEGER NOT NULL,
  evidence   INTEGER NOT NULL,
  PRIMARY KEY(blob_id, procedure, allocation),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

-- One memory location. kind follows MemoryLocationKind: Field (base,
-- member locator id), Property (base, property_key text id), Static
-- (member), Index (base, index_value, constant_index, index_identity),
-- Dereference (base holds the address value), LexicalCell (binding),
-- Capture (lexical_parent procedure, binding). value_copy follows
-- MemoryValueCopy, with value_copy_identity (IndexedLocationIdentity) for
-- BackingStore.
CREATE TABLE semantic_ir_memory_locations(
  blob_id             INTEGER NOT NULL,
  procedure           INTEGER NOT NULL,
  location            INTEGER NOT NULL,
  kind                INTEGER NOT NULL CHECK(kind BETWEEN 0 AND 6),
  base                INTEGER,
  member              INTEGER,
  property_key        INTEGER,
  index_value         INTEGER,
  constant_index      TEXT,
  index_identity      INTEGER CHECK(index_identity BETWEEN 0 AND 1),
  lexical_parent      INTEGER,
  binding             INTEGER,
  value_copy          INTEGER NOT NULL CHECK(value_copy BETWEEN 0 AND 3),
  value_copy_identity INTEGER CHECK(value_copy_identity BETWEEN 0 AND 1),
  source              INTEGER NOT NULL,
  evidence            INTEGER NOT NULL,
  PRIMARY KEY(blob_id, procedure, location),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

-- One capture binding. target is a procedure, environment an allocation,
-- captured a value (captured_kind 0) or memory location (captured_kind 1),
-- destination a memory location of the target procedure. mode follows
-- CaptureMode, with mode_text (text id) for LanguageDefined.
CREATE TABLE semantic_ir_captures(
  blob_id       INTEGER NOT NULL,
  procedure     INTEGER NOT NULL,
  capture       INTEGER NOT NULL,
  point         INTEGER NOT NULL,
  callable      INTEGER NOT NULL,
  target        INTEGER NOT NULL,
  environment   INTEGER NOT NULL,
  captured_kind INTEGER NOT NULL CHECK(captured_kind BETWEEN 0 AND 1),
  captured      INTEGER NOT NULL,
  destination   INTEGER NOT NULL,
  mode          INTEGER NOT NULL CHECK(mode BETWEEN 0 AND 6),
  mode_text     INTEGER,
  source        INTEGER NOT NULL,
  evidence      INTEGER NOT NULL,
  PRIMARY KEY(blob_id, procedure, capture),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

-- One call site. invocation_mode follows CallInvocationMode and
-- execution_timing ExecutionTiming. normal_results is a JSONB array of value
-- ids, NULL when empty. target_resolution follows CallableTargetResolution;
-- targets is a procedure-local group id into semantic_ir_callable_targets,
-- NULL when the candidate list is empty. The continuations follow
-- ControlContinuation; a *_target column is non-null exactly when its code
-- is 0 (Target).
CREATE TABLE semantic_ir_call_sites(
  blob_id                  INTEGER NOT NULL,
  procedure                INTEGER NOT NULL,
  call_site                INTEGER NOT NULL,
  point                    INTEGER NOT NULL,
  invocation_mode          INTEGER NOT NULL CHECK(invocation_mode BETWEEN 0 AND 1),
  execution_timing         INTEGER NOT NULL CHECK(execution_timing BETWEEN 0 AND 9),
  callee                   INTEGER NOT NULL,
  receiver                 INTEGER,
  result                   INTEGER,
  thrown                   INTEGER,
  normal_results           BLOB CHECK(normal_results IS NULL OR json_valid(normal_results, 8)),
  target_resolution        INTEGER NOT NULL CHECK(target_resolution BETWEEN 0 AND 5),
  targets                  INTEGER,
  target_evidence          INTEGER NOT NULL,
  normal_continuation      INTEGER NOT NULL CHECK(normal_continuation BETWEEN 0 AND 5),
  normal_target            INTEGER,
  exceptional_continuation INTEGER NOT NULL CHECK(exceptional_continuation BETWEEN 0 AND 5),
  exceptional_target       INTEGER,
  source                   INTEGER NOT NULL,
  evidence                 INTEGER NOT NULL,
  CHECK(target_resolution NOT IN (2, 3) OR targets IS NULL),
  CHECK((normal_continuation = 0) = (normal_target IS NOT NULL)),
  CHECK((exceptional_continuation = 0) = (exceptional_target IS NOT NULL)),
  PRIMARY KEY(blob_id, procedure, call_site),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

-- One argument of one call site, in argument order. expansion follows
-- CallArgumentExpansion; domain follows ArgumentDomain (NULL for
-- Unclassified) with domain_text (text id) for LanguageDefined; keyword is
-- a text id.
CREATE TABLE semantic_ir_call_arguments(
  blob_id     INTEGER NOT NULL,
  procedure   INTEGER NOT NULL,
  call_site   INTEGER NOT NULL,
  ordinal     INTEGER NOT NULL,
  value       INTEGER NOT NULL,
  expansion   INTEGER NOT NULL CHECK(expansion BETWEEN 0 AND 2),
  domain      INTEGER CHECK(domain BETWEEN 0 AND 3),
  domain_text INTEGER,
  keyword     INTEGER,
  PRIMARY KEY(blob_id, procedure, call_site, ordinal),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

-- One candidate of one callable target group. Group ids are assigned in
-- encounter order over call sites, then events, then drops. kind follows
-- CallableTarget: Local (local_procedure), Unmaterialized and External
-- (locator id), Artifact (artifact_identity, the serde JSON of
-- AnonymousCallableIdentity).
CREATE TABLE semantic_ir_callable_targets(
  blob_id           INTEGER NOT NULL,
  procedure         INTEGER NOT NULL,
  targets           INTEGER NOT NULL,
  ordinal           INTEGER NOT NULL,
  kind              INTEGER NOT NULL CHECK(kind BETWEEN 0 AND 3),
  local_procedure   INTEGER,
  locator           INTEGER,
  artifact_identity BLOB CHECK(artifact_identity IS NULL OR json_valid(artifact_identity, 8)),
  PRIMARY KEY(blob_id, procedure, targets, ordinal),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

-- One source mapping. kind follows SourceMappingKind; ast_node is the
-- structural node's normalized id, whose content half is the head's
-- content_digest.
CREATE TABLE semantic_ir_source_mappings(
  blob_id   INTEGER NOT NULL,
  procedure INTEGER NOT NULL,
  mapping   INTEGER NOT NULL,
  locator   INTEGER NOT NULL,
  kind      INTEGER NOT NULL CHECK(kind BETWEEN 0 AND 2),
  ast_node  INTEGER,
  PRIMARY KEY(blob_id, procedure, mapping),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

-- One statement entry site, in producer order.
CREATE TABLE semantic_ir_statement_entries(
  blob_id   INTEGER NOT NULL,
  procedure INTEGER NOT NULL,
  ordinal   INTEGER NOT NULL,
  source    INTEGER NOT NULL,
  evidence  INTEGER NOT NULL,
  point     INTEGER NOT NULL,
  PRIMARY KEY(blob_id, procedure, ordinal),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

-- One loop site, in producer order: header and body are points.
CREATE TABLE semantic_ir_loop_sites(
  blob_id   INTEGER NOT NULL,
  procedure INTEGER NOT NULL,
  ordinal   INTEGER NOT NULL,
  source    INTEGER NOT NULL,
  evidence  INTEGER NOT NULL,
  header    INTEGER NOT NULL,
  body      INTEGER NOT NULL,
  PRIMARY KEY(blob_id, procedure, ordinal),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

-- One evidence row. proof follows ProofStatus and completeness
-- EvidenceCompleteness; the reasons are text ids. sources is a JSONB array
-- of source mapping ids.
CREATE TABLE semantic_ir_evidence(
  blob_id             INTEGER NOT NULL,
  procedure           INTEGER NOT NULL,
  evidence            INTEGER NOT NULL,
  proof               INTEGER NOT NULL CHECK(proof BETWEEN 0 AND 1),
  proof_reason        INTEGER,
  completeness        INTEGER NOT NULL CHECK(completeness BETWEEN 0 AND 1),
  completeness_reason INTEGER,
  sources             BLOB NOT NULL CHECK(json_valid(sources, 8)),
  PRIMARY KEY(blob_id, procedure, evidence),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

-- One semantic gap. subject follows SemanticGapSubject: Value,
-- MemoryLocation, Capture and CallSite use subject_a; CallContinuation uses
-- subject_a (call site) and subject_b (0 normal, 1 exceptional);
-- AsyncContinuation uses subject_a (suspend point) and subject_b.
-- capability follows SemanticCapability::ALL; impacts is the
-- SemanticGapImpacts bit set; kind follows SemanticGapKind; budget_dimension
-- follows SemanticBudgetDimension; discharge follows SemanticGapDischarge;
-- detail is a text id.
CREATE TABLE semantic_ir_gaps(
  blob_id          INTEGER NOT NULL,
  procedure        INTEGER NOT NULL,
  gap              INTEGER NOT NULL,
  point            INTEGER NOT NULL,
  subject          INTEGER NOT NULL CHECK(subject BETWEEN 0 AND 7),
  subject_a        INTEGER,
  subject_b        INTEGER,
  capability       INTEGER NOT NULL CHECK(capability BETWEEN 0 AND 33),
  impacts          INTEGER NOT NULL CHECK(impacts BETWEEN 0 AND 127),
  kind             INTEGER NOT NULL CHECK(kind BETWEEN 0 AND 4),
  budget_dimension INTEGER CHECK(budget_dimension BETWEEN 0 AND 15),
  budget_limit     INTEGER,
  budget_attempted INTEGER,
  discharge        INTEGER NOT NULL CHECK(discharge BETWEEN 0 AND 12),
  detail           INTEGER NOT NULL,
  source           INTEGER NOT NULL,
  evidence         INTEGER NOT NULL,
  PRIMARY KEY(blob_id, procedure, gap),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

-- One basic block. points is a JSONB array of point ids in block order.
CREATE TABLE semantic_ir_blocks(
  blob_id   INTEGER NOT NULL,
  procedure INTEGER NOT NULL,
  block     INTEGER NOT NULL,
  points    BLOB NOT NULL CHECK(json_valid(points, 8)),
  source    INTEGER NOT NULL,
  evidence  INTEGER NOT NULL,
  PRIMARY KEY(blob_id, procedure, block),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

-- One program point; its events are in semantic_ir_events.
CREATE TABLE semantic_ir_points(
  blob_id   INTEGER NOT NULL,
  procedure INTEGER NOT NULL,
  point     INTEGER NOT NULL,
  block     INTEGER NOT NULL,
  source    INTEGER NOT NULL,
  evidence  INTEGER NOT NULL,
  PRIMARY KEY(blob_id, procedure, point),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

-- One event of one program point; ordinal is its position in the point's
-- event list. effect follows SemanticEffect. Columns per effect:
-- Assignment: value_a target, value_b value. AggregateInitializer: value_a
-- aggregate, value_b value, locator selector. ValueFlow: sub_kind
-- (ValueFlowKind), value_a source, value_b target, payload in
-- semantic_ir_event_transfers or semantic_ir_event_offsets. ValueUse:
-- sub_kind (ValueUseKind), value_a. Allocation: allocation. MemoryLoad:
-- sub_kind (MemoryAccessKind), location, value_a result. MemoryStore:
-- sub_kind, location, value_a value. Synchronization: sub_kind
-- (SynchronizationOperation), value_a subject, payload in
-- semantic_ir_event_synchronizations. CallableCreation and
-- CallableReference: value_a result, sub_kind (CallableReferenceKind),
-- value_b qualifier, value_c bound receiver, allocation environment,
-- targets in semantic_ir_event_callables. CaptureBind: capture. Invoke:
-- call_site. CallContinuation: call_site, sub_kind (CallContinuationKind).
-- ProcedureReturn and Throw: value_a. AsyncSuspend: value_a awaited,
-- continuations in semantic_ir_event_async_suspends. AsyncResume:
-- suspend_point, sub_kind (AsyncResumeKind), value_a result. Gap: gap.
CREATE TABLE semantic_ir_events(
  blob_id       INTEGER NOT NULL,
  procedure     INTEGER NOT NULL,
  point         INTEGER NOT NULL,
  ordinal       INTEGER NOT NULL,
  effect        INTEGER NOT NULL CHECK(effect BETWEEN 0 AND 20),
  sub_kind      INTEGER,
  value_a       INTEGER,
  value_b       INTEGER,
  value_c       INTEGER,
  location      INTEGER,
  allocation    INTEGER,
  call_site     INTEGER,
  capture       INTEGER,
  gap           INTEGER,
  locator       INTEGER,
  suspend_point INTEGER,
  source        INTEGER NOT NULL,
  evidence      INTEGER NOT NULL,
  PRIMARY KEY(blob_id, procedure, point, ordinal),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

-- The transfer of a ValueFlow Transfer event. transfer_kind follows
-- TransferKind; transfer_detail follows MoveInvalidation for Move and
-- ValuePreservation for Conversion; operation follows TransferOperation,
-- with call_site for CallSite and digest for CallArgumentConversion and
-- ValueCarrierAdaptation.
CREATE TABLE semantic_ir_event_transfers(
  blob_id         INTEGER NOT NULL,
  procedure       INTEGER NOT NULL,
  point           INTEGER NOT NULL,
  ordinal         INTEGER NOT NULL,
  transfer_kind   INTEGER NOT NULL CHECK(transfer_kind BETWEEN 0 AND 5),
  transfer_detail INTEGER,
  operation       INTEGER NOT NULL CHECK(operation BETWEEN 0 AND 4),
  call_site       INTEGER,
  digest          BLOB CHECK(digest IS NULL OR length(digest) = 32),
  PRIMARY KEY(blob_id, procedure, point, ordinal),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

-- The payload of a ValueFlow BackingStore, BackingStoreAlternative,
-- IntegerOffset or IndexedReturn event. offset_kind follows
-- BackingStoreOffset (Zero, Constant with magnitude, Value with
-- offset_value); BackingStoreAlternative adds allocation; IntegerOffset uses
-- negative and magnitude; IndexedReturn uses return_ordinal.
CREATE TABLE semantic_ir_event_offsets(
  blob_id        INTEGER NOT NULL,
  procedure      INTEGER NOT NULL,
  point          INTEGER NOT NULL,
  ordinal        INTEGER NOT NULL,
  offset_kind    INTEGER CHECK(offset_kind BETWEEN 0 AND 2),
  magnitude      TEXT,
  offset_value   INTEGER,
  negative       INTEGER CHECK(negative IN (0, 1)),
  allocation     INTEGER,
  return_ordinal INTEGER,
  PRIMARY KEY(blob_id, procedure, point, ordinal),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

-- The targets of a CallableCreation or CallableReference event.
-- target_resolution follows CallableTargetResolution; targets is a group id
-- into semantic_ir_callable_targets, NULL when the candidate list is empty.
CREATE TABLE semantic_ir_event_callables(
  blob_id           INTEGER NOT NULL,
  procedure         INTEGER NOT NULL,
  point             INTEGER NOT NULL,
  ordinal           INTEGER NOT NULL,
  target_resolution INTEGER NOT NULL CHECK(target_resolution BETWEEN 0 AND 5),
  targets           INTEGER,
  target_evidence   INTEGER NOT NULL,
  PRIMARY KEY(blob_id, procedure, point, ordinal),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

-- The payload of a Synchronization event that has one. payload_kind is
-- 0 Send (value, copy_kind following SynchronizationPayloadCopy,
-- copy_identity for BackingStore) or 1 Receive (value is the result).
CREATE TABLE semantic_ir_event_synchronizations(
  blob_id       INTEGER NOT NULL,
  procedure     INTEGER NOT NULL,
  point         INTEGER NOT NULL,
  ordinal       INTEGER NOT NULL,
  payload_kind  INTEGER NOT NULL CHECK(payload_kind BETWEEN 0 AND 1),
  value         INTEGER NOT NULL,
  copy_kind     INTEGER CHECK(copy_kind BETWEEN 0 AND 2),
  copy_identity INTEGER CHECK(copy_identity BETWEEN 0 AND 1),
  PRIMARY KEY(blob_id, procedure, point, ordinal),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

-- The resume continuations of an AsyncSuspend event, following
-- ControlContinuation; a *_target column is non-null exactly when its code
-- is 0.
CREATE TABLE semantic_ir_event_async_suspends(
  blob_id                  INTEGER NOT NULL,
  procedure                INTEGER NOT NULL,
  point                    INTEGER NOT NULL,
  ordinal                  INTEGER NOT NULL,
  normal_continuation      INTEGER NOT NULL CHECK(normal_continuation BETWEEN 0 AND 5),
  normal_target            INTEGER,
  exceptional_continuation INTEGER NOT NULL CHECK(exceptional_continuation BETWEEN 0 AND 5),
  exceptional_target       INTEGER,
  PRIMARY KEY(blob_id, procedure, point, ordinal),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

-- One control edge, in the order the lowerer emitted them. kind follows
-- ControlEdgeKind.
CREATE TABLE semantic_ir_control_edges(
  blob_id      INTEGER NOT NULL,
  procedure    INTEGER NOT NULL,
  ordinal      INTEGER NOT NULL,
  source_point INTEGER NOT NULL,
  target_point INTEGER NOT NULL,
  kind         INTEGER NOT NULL CHECK(kind BETWEEN 0 AND 8),
  source       INTEGER NOT NULL,
  evidence     INTEGER NOT NULL,
  PRIMARY KEY(blob_id, procedure, ordinal),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

-- One guard fact. predicate follows GuardPredicate: ConstantBoolean (flag
-- value), NullComparison (flag null_on_true), ConstantEquality (flag
-- negated, constant), OrderedIntegerComparison and OrderedFloatComparison
-- (relation following IntegerComparison, constant), NanComparison (flag
-- nan_on_true), InstanceOf (operand_a value, operand_b classes), ExactClass
-- (operand_a, operand_b, flag exact_on_true), HasMember (operand_a value,
-- operand_b member), Truthy (operand_a), Opaque (digest, the u64 condition
-- digest). Each arm is a target point and a ControlEdgeKind, both NULL when
-- the arm is absent.
CREATE TABLE semantic_ir_guard_facts(
  blob_id      INTEGER NOT NULL,
  procedure    INTEGER NOT NULL,
  guard        INTEGER NOT NULL,
  point        INTEGER NOT NULL,
  subject      INTEGER,
  predicate    INTEGER NOT NULL CHECK(predicate BETWEEN 0 AND 10),
  flag         INTEGER CHECK(flag IN (0, 1)),
  relation     INTEGER CHECK(relation BETWEEN 0 AND 3),
  constant     INTEGER,
  operand_a    INTEGER,
  operand_b    INTEGER,
  digest       INTEGER,
  true_target  INTEGER,
  true_kind    INTEGER,
  false_target INTEGER,
  false_kind   INTEGER,
  source       INTEGER NOT NULL,
  evidence     INTEGER NOT NULL,
  PRIMARY KEY(blob_id, procedure, guard),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

-- One switch fact. kind follows SwitchFactKind and selector_domain
-- SwitchSelectorDomain. The default edge is a source point, a target point
-- and a ControlEdgeKind, all NULL when absent.
CREATE TABLE semantic_ir_switch_facts(
  blob_id              INTEGER NOT NULL,
  procedure            INTEGER NOT NULL,
  switch               INTEGER NOT NULL,
  kind                 INTEGER NOT NULL CHECK(kind BETWEEN 0 AND 2),
  point                INTEGER NOT NULL,
  selector             INTEGER,
  selector_domain      INTEGER NOT NULL CHECK(selector_domain BETWEEN 0 AND 1),
  default_present      INTEGER NOT NULL CHECK(default_present IN (0, 1)),
  default_source_point INTEGER,
  default_target       INTEGER,
  default_kind         INTEGER,
  source               INTEGER NOT NULL,
  evidence             INTEGER NOT NULL,
  PRIMARY KEY(blob_id, procedure, switch),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

-- One case of one switch fact, in case order. edge_kind follows
-- ControlEdgeKind.
CREATE TABLE semantic_ir_switch_cases(
  blob_id      INTEGER NOT NULL,
  procedure    INTEGER NOT NULL,
  switch       INTEGER NOT NULL,
  ordinal      INTEGER NOT NULL,
  value        INTEGER NOT NULL,
  source_point INTEGER NOT NULL,
  target_point INTEGER NOT NULL,
  edge_kind    INTEGER NOT NULL,
  PRIMARY KEY(blob_id, procedure, switch, ordinal),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

-- Lifecycle and pointer rows. A place is place_kind 0 LocalBinding
-- (place_locator, a locator id) or 1 MemoryLocation (place_location).

-- One drop fact. behavior is 0 Trivial or 1 Destructor, whose resolution
-- follows CallableTargetResolution with destructor_targets a group id into
-- semantic_ir_callable_targets, NULL when the candidate list is empty.
CREATE TABLE semantic_ir_drops(
  blob_id               INTEGER NOT NULL,
  procedure             INTEGER NOT NULL,
  ordinal               INTEGER NOT NULL,
  place_kind            INTEGER NOT NULL CHECK(place_kind BETWEEN 0 AND 1),
  place_locator         INTEGER,
  place_location        INTEGER,
  point                 INTEGER NOT NULL,
  behavior              INTEGER NOT NULL CHECK(behavior BETWEEN 0 AND 1),
  destructor_resolution INTEGER CHECK(destructor_resolution BETWEEN 0 AND 5),
  destructor_targets    INTEGER,
  source                INTEGER NOT NULL,
  evidence              INTEGER NOT NULL,
  PRIMARY KEY(blob_id, procedure, ordinal),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

-- One move-out fact. state_after follows MoveOutState.
CREATE TABLE semantic_ir_move_outs(
  blob_id        INTEGER NOT NULL,
  procedure      INTEGER NOT NULL,
  ordinal        INTEGER NOT NULL,
  place_kind     INTEGER NOT NULL CHECK(place_kind BETWEEN 0 AND 1),
  place_locator  INTEGER,
  place_location INTEGER,
  point          INTEGER NOT NULL,
  source_value   INTEGER NOT NULL,
  target_value   INTEGER NOT NULL,
  state_after    INTEGER NOT NULL CHECK(state_after BETWEEN 0 AND 2),
  source         INTEGER NOT NULL,
  evidence       INTEGER NOT NULL,
  PRIMARY KEY(blob_id, procedure, ordinal),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

-- One scope end. at_kind is 0 Point (at_point) or 1 Edge (edge_source,
-- edge_target, edge_kind following ControlEdgeKind).
CREATE TABLE semantic_ir_scope_ends(
  blob_id        INTEGER NOT NULL,
  procedure      INTEGER NOT NULL,
  ordinal        INTEGER NOT NULL,
  place_kind     INTEGER NOT NULL CHECK(place_kind BETWEEN 0 AND 1),
  place_locator  INTEGER,
  place_location INTEGER,
  at_kind        INTEGER NOT NULL CHECK(at_kind BETWEEN 0 AND 1),
  at_point       INTEGER,
  edge_source    INTEGER,
  edge_target    INTEGER,
  edge_kind      INTEGER,
  source         INTEGER NOT NULL,
  evidence       INTEGER NOT NULL,
  PRIMARY KEY(blob_id, procedure, ordinal),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

-- One pointer origin. kind is 0 StackPlace (place columns) or 1 Allocation
-- (allocation); byte_extent is a u128 magnitude.
CREATE TABLE semantic_ir_pointer_origins(
  blob_id        INTEGER NOT NULL,
  procedure      INTEGER NOT NULL,
  origin         INTEGER NOT NULL,
  point          INTEGER NOT NULL,
  kind           INTEGER NOT NULL CHECK(kind BETWEEN 0 AND 1),
  place_kind     INTEGER,
  place_locator  INTEGER,
  place_location INTEGER,
  allocation     INTEGER,
  byte_extent    TEXT,
  source         INTEGER NOT NULL,
  evidence       INTEGER NOT NULL,
  PRIMARY KEY(blob_id, procedure, origin),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

-- One pointer alias. offset_kind follows PointerByteOffset: Exact
-- (offset_exact), Value (offset_value), Range (offset_min, offset_max),
-- Unknown; the offsets are i128 magnitudes. strength follows
-- PointerRelationStrength.
CREATE TABLE semantic_ir_pointer_aliases(
  blob_id      INTEGER NOT NULL,
  procedure    INTEGER NOT NULL,
  ordinal      INTEGER NOT NULL,
  point        INTEGER NOT NULL,
  pointer      INTEGER NOT NULL,
  origin       INTEGER NOT NULL,
  offset_kind  INTEGER NOT NULL CHECK(offset_kind BETWEEN 0 AND 3),
  offset_exact TEXT,
  offset_value INTEGER,
  offset_min   TEXT,
  offset_max   TEXT,
  strength     INTEGER NOT NULL CHECK(strength BETWEEN 0 AND 1),
  source       INTEGER NOT NULL,
  evidence     INTEGER NOT NULL,
  PRIMARY KEY(blob_id, procedure, ordinal),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

-- One pointer access. kind follows PointerAccessKind; width_kind follows
-- PointerAccessWidth: Exact (width_exact), ValueTimes (width_value,
-- width_multiplier), Unknown; the widths are u128 magnitudes.
CREATE TABLE semantic_ir_pointer_accesses(
  blob_id          INTEGER NOT NULL,
  procedure        INTEGER NOT NULL,
  ordinal          INTEGER NOT NULL,
  point            INTEGER NOT NULL,
  pointer          INTEGER NOT NULL,
  kind             INTEGER NOT NULL CHECK(kind BETWEEN 0 AND 2),
  width_kind       INTEGER NOT NULL CHECK(width_kind BETWEEN 0 AND 2),
  width_exact      TEXT,
  width_value      INTEGER,
  width_multiplier TEXT,
  source           INTEGER NOT NULL,
  evidence         INTEGER NOT NULL,
  PRIMARY KEY(blob_id, procedure, ordinal),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

-- One pointer invalidation. target_kind is 0 Pointer (target_value) or 1
-- Origin (target_origin); cause follows PointerInvalidationCause and
-- strength PointerRelationStrength.
CREATE TABLE semantic_ir_pointer_invalidations(
  blob_id       INTEGER NOT NULL,
  procedure     INTEGER NOT NULL,
  ordinal       INTEGER NOT NULL,
  point         INTEGER NOT NULL,
  target_kind   INTEGER NOT NULL CHECK(target_kind BETWEEN 0 AND 1),
  target_value  INTEGER,
  target_origin INTEGER,
  cause         INTEGER NOT NULL CHECK(cause BETWEEN 0 AND 3),
  strength      INTEGER NOT NULL CHECK(strength BETWEEN 0 AND 1),
  source        INTEGER NOT NULL,
  evidence      INTEGER NOT NULL,
  PRIMARY KEY(blob_id, procedure, ordinal),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

-- One incomplete fact. subject follows SemanticIncompleteSubject: Procedure,
-- Place (place columns), Value (value), PointerOrigin (origin).
-- reason_domain is 0 Lifecycle (reason follows LifecycleIncompleteReason)
-- or 1 Pointer (reason follows PointerIncompleteReason).
CREATE TABLE semantic_ir_incomplete_facts(
  blob_id        INTEGER NOT NULL,
  procedure      INTEGER NOT NULL,
  ordinal        INTEGER NOT NULL,
  point          INTEGER NOT NULL,
  subject        INTEGER NOT NULL CHECK(subject BETWEEN 0 AND 3),
  place_kind     INTEGER,
  place_locator  INTEGER,
  place_location INTEGER,
  value          INTEGER,
  origin         INTEGER,
  reason_domain  INTEGER NOT NULL CHECK(reason_domain BETWEEN 0 AND 1),
  reason         INTEGER NOT NULL CHECK(reason BETWEEN 0 AND 9),
  source         INTEGER NOT NULL,
  evidence       INTEGER NOT NULL,
  PRIMARY KEY(blob_id, procedure, ordinal),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

-- The written receiver type of one method call. member is a text id;
-- receiver_type is a JSONB array of text ids, outermost segment first.
CREATE TABLE semantic_ir_receiver_type_facts(
  blob_id       INTEGER NOT NULL,
  procedure     INTEGER NOT NULL,
  call_site     INTEGER NOT NULL,
  member        INTEGER NOT NULL,
  receiver_type BLOB NOT NULL CHECK(json_valid(receiver_type, 8)),
  PRIMARY KEY(blob_id, procedure, call_site),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
