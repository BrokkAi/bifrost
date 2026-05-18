# ExecPlans

When writing complex features or significant refactors, use an ExecPlan (as described in .agent/PLANS.md) from design to implementation.

# Expectations

When there is a clear next step towards your goal (in or out of ExecPlan), you always continue to execute it without
stopping to ask. If you have made material progress, commit a multiline checkpoint first explaining changes-so-far
in detail, especially the "why", I can get the "what" from the diff.

# Analyzer Test Guidance

When adding or refactoring analyzer tests that need small ad hoc projects, prefer the shared inline test harness in
`tests/common/inline_project.rs` over handwritten `tempdir` plus `ProjectFile::write(...)` setup.

Use `InlineTestProject` by default for tests that define a few files inline. It keeps temp-root management automatic,
hides absolute-path handling, and can infer analyzer languages from file extensions or accept an explicit language when
the test should stay single-language.

Prefer handwritten fixture directories or bespoke setup only when the test genuinely needs a larger reusable corpus or
filesystem behavior that is awkward to express inline.

# Rust CI Checks

Before pushing Rust changes, run the same core checks that CI enforces locally when practical.

At minimum, run `cargo fmt --check` and `cargo clippy --all-targets --all-features -- -D warnings`. If clippy or fmt
fails, fix that locally before pushing rather than waiting for the CI matrix to report it back.
