CREATE INDEX python_member_operations_any_writes ON python_member_operations(effect,blob_id,site) WHERE name_kind=2 AND effect IN (1,2);
