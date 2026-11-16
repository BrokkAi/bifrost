These small archives are explicitly test-only simulated compiler distributions.
They derive from the adjacent `rustdoc-contract` engine fixtures, not from a
released Rust toolchain. They contain no executable code or product pack.

`generate.py` creates deterministic GNU tar archives compressed with xz. It
removes optional crate-version metadata, supplies one concrete Box impl of the
cross-document core trait, and adds a duplicate canonical path in the ambiguous
case. The zero compiler commit and synthetic version are deliberate test data.

The test hashes each archive and verifies actual member equality before obtaining
any authority. No test constructs a verified token directly. Keeping compressed
fixtures avoids adding an encoder to the workspace's production dependency set.
