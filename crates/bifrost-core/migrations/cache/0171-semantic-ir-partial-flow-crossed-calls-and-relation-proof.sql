-- The calls each partial flow crossed (rows version 3) and whether the
-- procedure's relations are proven complete (rows version 4).
--
-- crossed is a JSONB array of arrays of call-site ids of the flow's
-- procedure, positional: one sorted array per distinct class of the flow's
-- paths, holding the call sites the value went past from the call's point to
-- the call's own continuation, with no array a superset of another. A flow
-- that crosses no call is [[]].
-- The value does not pass through those calls, but the ICFG engine reaches a
-- call's continuation only over continuation edges whose proof and
-- completeness come from the call's dispatch, so the composition derives a
-- flow's quality from them at query time.
--
-- The default fills the rows written before this column existed. Their heads
-- were written under rows version 2, whose producer epoch is no longer
-- active, so no reader serves them and republishing the blob replaces them.
ALTER TABLE semantic_ir_partial_flows
  ADD COLUMN crossed BLOB NOT NULL DEFAULT X'1B0B' CHECK(json_valid(crossed, 8));

-- relations_complete is 1 when every relation of the procedure's value-flow
-- snapshot is proven complete. The ICFG engine reports a procedure with an
-- unproven relation as an incomplete snapshot before it looks at any gap,
-- and no other head column says so: open covers gaps and call continuations,
-- and detail is the projection's status label. The composition reads it to
-- answer the same openness as the ICFG engine.
--
-- The default 0 only fills heads written under rows version 3, whose producer
-- epoch is no longer active, so no reader serves them.
ALTER TABLE semantic_ir_partial_flow_heads
  ADD COLUMN relations_complete INTEGER NOT NULL DEFAULT 0 CHECK(relations_complete IN (0, 1));
