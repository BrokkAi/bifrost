//! Differential test for the Go unit summaries (`store/go_unit_summaries.rs`).
//!
//! A real Go workspace is built and published through the production path, which
//! reconciles the summaries. The test then asks the incumbent readers the same
//! questions the summary answers and compares the answers as sets:
//!
//! - the unit set, against the package placement the point reader uses
//!   (`CALLER_PACKAGE`) for every selected file;
//! - each unit's member files, against the same-package peers
//!   (`PACKAGE_PEER_MOUNTS`);
//! - each unit's export rows, against the package members the same-package reader
//!   (`selected_package_members_by_lookup`) reads per peer;
//! - each unit's import rows, against the `(binding, package)` pairs the import
//!   binding reader (`go_file_import_context_with_role`) publishes.
//!
//! Any difference is printed in full, one side at a time.
