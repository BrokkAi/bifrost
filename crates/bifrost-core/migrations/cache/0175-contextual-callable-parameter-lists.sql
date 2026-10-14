ALTER TABLE resolution_callable_parameter_lists
  ADD COLUMN contextual INTEGER NOT NULL DEFAULT 0
  CHECK(contextual IN (0, 1));
