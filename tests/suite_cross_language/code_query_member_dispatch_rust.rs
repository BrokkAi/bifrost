//! Rust member-dispatch attribution conformance for #1477, Milestone 3.
//!
//! Rust has two production `receiver.member` seams and they are attributed
//! differently on purpose, because they do different work:
//!
//! - The direct lookup asks the declaration store for `owner.member` and walks
//!   no hierarchy. Every candidate it admits is depth zero with an empty route.
//!   Its dispatch bucket still is not always the inherent one: a member an
//!   `impl Trait for Type` block declares is indexed under `Type` and found
//!   here, and the shape of its declaration is what says so.
//! - The trait fallback runs only when the direct lookup found nothing. It
//!   expands the receiver type's direct ancestors, which is one real hierarchy
//!   hop across an implementation edge.
//!
//! Anything else stays unattributed. The last test locks that in: a seam that
//! cannot name the owner it found the member on reports *absence*, never a
//! plausible-looking depth zero.

use crate::common::InlineTestProject;
use brokk_bifrost::analyzer::structural::{CodeQuery, CodeQueryResult, execute_workspace};
use brokk_bifrost::{AnalyzerConfig, WorkspaceAnalyzer};
use serde_json::{Value, json};

fn run(files: &[(&str, &str)], query: Value) -> CodeQueryResult {
    let mut project = InlineTestProject::new();
    for (path, source) in files {
        project = project.file(*path, *source);
    }
    let project = project.build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let query = CodeQuery::from_json(&query).expect("query should parse");
    execute_workspace(&workspace, &query)
}

fn serialized(result: &CodeQueryResult) -> Value {
    serde_json::to_value(result).expect("query result should serialize")
}

fn rows(value: &Value) -> &Vec<Value> {
    value["results"].as_array().expect("results array")
}

fn candidates_at(files: &[(&str, &str)], role: &str) -> Value {
    serialized(&run(
        files,
        json!({
            "where": ["app.rs"],
            "occurrences": { "role": [role] },
            "steps": [{"op": "candidates_of"}],
            "result_detail": "full"
        }),
    ))
}

fn member_candidates(source: &str) -> Value {
    candidates_at(&[("app.rs", source)], "member_position")
}

fn selected(value: &Value) -> Vec<&Value> {
    rows(value)
        .iter()
        .filter(|row| row["outcome"] == "selected")
        .collect()
}

/// A method the receiver type's own inherent `impl` block declares, with a
/// same-name decoy type present: the resolver finds it on the receiver's own
/// type with no hierarchy walk, so the row states depth zero, an inherent
/// bucket, and the receiver's type as the exact owner.
#[test]
fn rust_inherent_method_is_attributed_at_depth_zero() {
    let value = member_candidates(
        "struct Service;\n\
         impl Service { fn run(&self) {} }\n\
         struct Decoy;\n\
         impl Decoy { fn run(&self) {} }\n\
         fn caller(service: Service) { service.run(); }\n",
    );
    let selected = selected(&value);
    assert_eq!(selected.len(), 1, "{value}");
    let row = selected[0];
    assert_eq!(
        row["candidate"]["unit"]["fq_name"], "Service.run",
        "{value}"
    );
    assert_eq!(row["owner"]["fq_name"], "Service", "{value}");
    assert_eq!(row["hierarchy_depth"], 0, "{value}");
    assert_eq!(row["dispatch_tier"], "inherent_or_direct", "{value}");
    // The Rust member seams check the member's namespace and nothing about the
    // call shape, so the applicability axis (#1478) is untested here.
    assert_eq!(row["applicability"], "unknown", "{value}");
}

/// A trait's default method reached through the receiver: the direct lookup
/// finds nothing under `Service.run`, and the production fallback expands
/// `Service`'s direct ancestors to reach `Runner`. The row therefore owns the
/// trait, one hop away, in the trait bucket -- and the same-name decoy type,
/// which is not in the receiver's hierarchy, never appears.
#[test]
fn rust_trait_default_method_is_attributed_through_one_implementation_hop() {
    let value = member_candidates(
        "struct Service;\n\
         trait Runner { fn run(&self) {} }\n\
         impl Runner for Service {}\n\
         struct Decoy;\n\
         impl Decoy { fn run(&self) {} }\n\
         fn caller(service: Service) { service.run(); }\n",
    );
    let selected = selected(&value);
    assert_eq!(selected.len(), 1, "{value}");
    let row = selected[0];
    assert_eq!(row["candidate"]["unit"]["fq_name"], "Runner.run", "{value}");
    assert_eq!(row["owner"]["fq_name"], "Runner", "{value}");
    assert_eq!(row["hierarchy_depth"], 1, "{value}");
    assert_eq!(row["dispatch_tier"], "trait_or_interface", "{value}");
    assert!(
        rows(&value)
            .iter()
            .all(|row| row["candidate"]["unit"]["fq_name"] != "Decoy.run"),
        "a same-name member outside the receiver's hierarchy is never considered: {value}"
    );
}

/// A method declared by an `impl Trait for Type` block is indexed under the
/// type, so the *direct* lookup finds it: depth zero, no route. The bucket is
/// still the trait one, because the declaration's own shape proves it is a
/// trait implementation rather than an inherent member. Depth and bucket are
/// independent axes and this fixture is where they disagree.
#[test]
fn rust_trait_impl_member_is_a_direct_find_in_the_trait_bucket() {
    let value = member_candidates(
        "struct Service;\n\
         trait Runner { fn run(&self); }\n\
         impl Runner for Service { fn run(&self) {} }\n\
         fn caller(service: Service) { service.run(); }\n",
    );
    let selected = selected(&value);
    assert_eq!(selected.len(), 1, "{value}");
    let row = selected[0];
    assert_eq!(
        row["candidate"]["unit"]["fq_name"], "Service.run",
        "{value}"
    );
    assert_eq!(row["owner"]["fq_name"], "Service", "{value}");
    assert_eq!(row["hierarchy_depth"], 0, "{value}");
    assert_eq!(row["dispatch_tier"], "trait_or_interface", "{value}");
}

/// Rust resolves an inherent method before a trait method of the same name,
/// and the trace states the win as a direct find. The trait's default method
/// is never computed: the direct lookup succeeds, so the ancestor walk that
/// would have reached `Runner.run` never runs. No row may therefore claim the
/// trait declaration was considered and lost.
#[test]
fn rust_inherent_member_outranks_the_trait_default_method() {
    let value = member_candidates(
        "struct Service;\n\
         trait Runner { fn run(&self) {} }\n\
         impl Runner for Service {}\n\
         impl Service { fn run(&self) {} }\n\
         fn caller(service: Service) { service.run(); }\n",
    );
    let selected = selected(&value);
    assert_eq!(selected.len(), 1, "{value}");
    let row = selected[0];
    assert_eq!(
        row["candidate"]["unit"]["fq_name"], "Service.run",
        "{value}"
    );
    assert_eq!(row["owner"]["fq_name"], "Service", "{value}");
    assert_eq!(row["hierarchy_depth"], 0, "{value}");
    assert_eq!(row["dispatch_tier"], "inherent_or_direct", "{value}");
    assert!(
        rows(&value)
            .iter()
            .all(|row| row["candidate"]["unit"]["fq_name"] != "Runner.run"),
        "the hidden trait method is never computed by the production walk, so no \
         row may claim it was considered: {value}"
    );
}

/// The honesty rule. `Service::make()` is an associated call, which Rust's
/// occurrence model classifies as a value reference and which resolves through
/// the scoped-owner path, not through either instrumented member seam. That
/// path does not name the owner it found the member on, so its candidate row
/// carries *no* attribution at all. Absence is the correct report; a depth of
/// zero would be a claim the resolver never made.
#[test]
fn rust_associated_function_call_is_unattributed_not_depth_zero() {
    let value = candidates_at(
        &[(
            "app.rs",
            "struct Service;\n\
             impl Service { fn make() -> Service { Service } }\n\
             fn caller() { let _ = Service::make(); }\n",
        )],
        "value_reference",
    );
    let make = selected(&value)
        .into_iter()
        .find(|row| row["candidate"]["unit"]["fq_name"] == "Service.make")
        .unwrap_or_else(|| panic!("the associated call resolves to Service.make: {value}"));
    for field in [
        "owner",
        "owner_id",
        "hierarchy_depth",
        "dispatch_tier",
        "applicability",
    ] {
        assert!(
            make[field].is_null(),
            "an uninstrumented seam states nothing rather than a plausible default \
             for `{field}`: {value}"
        );
    }
}
