-- Semantic replay v2 stores cumulative counters, root work peaks and live
-- admissions as readable JSONB, never a serialized accounting blob. Old unit
-- products miss through the policy substrate epoch; keep their JSON readable
-- until the ordinary content/age sweep retires them.
ALTER TABLE policy_units RENAME COLUMN product TO legacy_product_json;
ALTER TABLE policy_units ADD COLUMN product BLOB NOT NULL DEFAULT X'0C'
  CHECK(json_valid(product, 8));
UPDATE policy_units SET product = jsonb(legacy_product_json);
ALTER TABLE policy_units DROP COLUMN legacy_product_json;
