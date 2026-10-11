-- Index the second foreign key of resolution_type_arguments. Without it a
-- parent check or cascade on resolution_semantic_catalog(blob_id, local_key)
-- searches every type-argument row of the blob for a matching argument_slot.
CREATE INDEX resolution_type_arguments_fk_argument_slot
  ON resolution_type_arguments(blob_id, argument_slot);
