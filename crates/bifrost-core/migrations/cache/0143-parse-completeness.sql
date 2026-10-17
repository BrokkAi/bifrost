-- Whether every declaration a parsed blob publishes is a reading of a
-- completed parse (#3501). A C or C++ parse that ends inside constructs it
-- never closed is persisted as 'partial' when a declaration lies inside the
-- outermost one; such a file is never reported complete. Every other blob is
-- 'complete', and so is every row written before this column, which the C++
-- extraction salt retires for C and C++ blobs.
ALTER TABLE blob_meta ADD COLUMN parse_completeness TEXT NOT NULL
  DEFAULT 'complete' CHECK(parse_completeness IN ('complete', 'partial'));
