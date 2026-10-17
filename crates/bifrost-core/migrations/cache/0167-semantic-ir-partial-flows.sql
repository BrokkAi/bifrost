-- Per-procedure partial flows.
--
-- A procedure's partial flows say which input port of the procedure can carry
-- a value to which output port without passing through a call. They are
-- computed from the procedure's own semantic IR rows (0164) when the blob is
-- prepared, so they share that blob's lifetime: the children below cascade
-- from semantic_ir_publications, and a procedure with no head row has no
-- flows. Every id column that names a port is a port id of the same
-- (blob_id, procedure); every text id and locator id is the blob's own, as in
-- 0164.

-- Ports are interned per procedure. kind follows the port kinds:
-- 0 Receiver; 1 Parameter (a = ordinal); 2 NormalReturn;
-- 3 IndexedNormalReturn (a = ordinal); 4 ExceptionalReturn;
-- 5 CallReceiver (a = call site); 6 CallArgument (a = call site,
-- b = argument ordinal); 7 CallResult (a = call site, b = result ordinal, NULL
-- for the singular result); 8 CallThrown (a = call site); 9 Capture
-- (a = memory location of the procedure, a capture slot); 10 Heap (root =
-- the port id of the root, which is kind 0, 1 or 9; selectors = a JSONB array
-- of [kind, operand] pairs with kind 0 field (operand = locator id), 1
-- property (operand = text id), 2 constant index (operand = text id of the
-- decimal), 3 exact index (operand = value id of the procedure), 4 any index
-- (operand NULL); tail 0 exact, 1 summary); 11 CaptureOut (a = the target
-- procedure of a capture binding, b = the destination memory location in that
-- target, a capture slot of the target).
-- A call site, a memory location and a value are procedure-local ids.
CREATE TABLE semantic_ir_ports(
  blob_id   INTEGER NOT NULL,
  procedure INTEGER NOT NULL,
  port      INTEGER NOT NULL,
  kind      INTEGER NOT NULL CHECK(kind BETWEEN 0 AND 11),
  a         INTEGER,
  b         INTEGER,
  root      INTEGER,
  selectors BLOB CHECK(selectors IS NULL OR json_valid(selectors, 8)),
  tail      INTEGER CHECK(tail IS NULL OR tail BETWEEN 0 AND 1),
  PRIMARY KEY(blob_id, procedure, port),
  CHECK((kind = 10) = (root IS NOT NULL)),
  FOREIGN KEY(blob_id, procedure, root) REFERENCES semantic_ir_ports(blob_id, procedure, port),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

-- One partial flow: a value entering at from_port can be at to_port inside the
-- procedure. uncertain is 1 when some path that carries it is not proven and
-- complete. The to_port index serves the backward search from a sink.
CREATE TABLE semantic_ir_partial_flows(
  blob_id   INTEGER NOT NULL,
  procedure INTEGER NOT NULL,
  from_port INTEGER NOT NULL,
  to_port   INTEGER NOT NULL,
  uncertain INTEGER NOT NULL CHECK(uncertain IN (0, 1)),
  PRIMARY KEY(blob_id, procedure, from_port, to_port),
  FOREIGN KEY(blob_id, procedure, from_port) REFERENCES semantic_ir_ports(blob_id, procedure, port),
  FOREIGN KEY(blob_id, procedure, to_port) REFERENCES semantic_ir_ports(blob_id, procedure, port),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE INDEX semantic_ir_partial_flows_to_port
  ON semantic_ir_partial_flows(blob_id, procedure, to_port);

-- The head of one procedure's flows. outcome: 0 complete, 1 truncated (the
-- relation projection's candidate set hit a limit), 2 exceeded_budget,
-- 3 error. Outcomes 0 and 1 carry the procedure's ports and flows; 2 and 3
-- carry none. detail is a text id: the error message for outcome 3; for
-- outcome 0 the label of a projection outcome that was not complete but whose
-- snapshot still yields flows (for example unknown); NULL otherwise. open is 1
-- when the procedure is open: a value-flow gap that is not discharged, or a
-- call continuation the IR does not resolve.
-- discharged_gaps is a JSONB array of gap ids.
CREATE TABLE semantic_ir_partial_flow_heads(
  blob_id         INTEGER NOT NULL,
  procedure       INTEGER NOT NULL,
  outcome         INTEGER NOT NULL CHECK(outcome BETWEEN 0 AND 3),
  detail          INTEGER,
  open            INTEGER NOT NULL CHECK(open IN (0, 1)),
  port_count      INTEGER NOT NULL CHECK(port_count >= 0),
  flow_count      INTEGER NOT NULL CHECK(flow_count >= 0),
  discharged_gaps BLOB NOT NULL CHECK(json_valid(discharged_gaps, 8)),
  PRIMARY KEY(blob_id, procedure),
  FOREIGN KEY(blob_id) REFERENCES semantic_ir_publications(blob_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
