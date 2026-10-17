ALTER TABLE source_rust_declaration_properties
  ADD COLUMN generated_surface INTEGER NOT NULL DEFAULT 0
    CHECK(generated_surface IN (0, 1));
