ALTER TABLE policy_evaluation_policies ADD COLUMN effective_grant TEXT CHECK(effective_grant IS NULL OR json_valid(effective_grant));
ALTER TABLE policy_evaluation_policies ADD COLUMN census_files INTEGER CHECK(census_files IS NULL OR census_files >= 0);
ALTER TABLE policy_evaluation_policies ADD COLUMN census_bytes INTEGER CHECK(census_bytes IS NULL OR census_bytes >= 0);
ALTER TABLE policy_evaluations ADD COLUMN effective_grant TEXT CHECK(effective_grant IS NULL OR json_valid(effective_grant));
ALTER TABLE policy_evaluations ADD COLUMN census_files INTEGER CHECK(census_files IS NULL OR census_files >= 0);
ALTER TABLE policy_evaluations ADD COLUMN census_bytes INTEGER CHECK(census_bytes IS NULL OR census_bytes >= 0);
ALTER TABLE policy_evaluations ADD COLUMN evidence_complete INTEGER CHECK(evidence_complete IS NULL OR evidence_complete IN (0, 1));
