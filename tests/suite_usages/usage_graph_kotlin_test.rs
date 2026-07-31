//! End-to-end `usage_graph` coverage for Kotlin (issue #1239, milestone 3).
//!
//! Drives the real MCP tool over a checked-in Kotlin workspace, so what is
//! asserted is what a consumer of `usage_graph`, `callers`/`callees`, relevance
//! ranking, or dead-code detection actually receives — not the edge builder's
//! internals.

use crate::common::usage_graph::{assert_every_edge_endpoint_is_a_node, has_edge, usage_graph_at};
use serde_json::Value;
use std::path::PathBuf;

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("usage-graph-kotlin")
}

fn usage_graph() -> Value {
    usage_graph_at(fixture_root(), "{}")
}

fn inbound(value: &Value, to: &str) -> Vec<String> {
    value["edges"]
        .as_array()
        .expect("edges array")
        .iter()
        .filter(|edge| edge["to"].as_str() == Some(to))
        .map(|edge| edge["from"].as_str().unwrap_or_default().to_string())
        .collect()
}

#[test]
fn resolves_instance_companion_object_and_constructor_calls() {
    let value = usage_graph();

    // `base.greet(..)` where `val base = Base()` — the local's type resolves the
    // receiver to the declaration the call binds to.
    assert!(
        has_edge(&value, "app.viaInstance", "lib.Base.greet"),
        "expected viaInstance -> lib.Base.greet: {}",
        value["edges"]
    );
    // `Base.of()` reaches a *companion* member through the enclosing class's own
    // name. That only resolves because companion-ness is a published fact.
    assert!(
        has_edge(&value, "app.viaCompanion", "lib.Base.Companion.of"),
        "expected viaCompanion -> lib.Base.Companion.of: {}",
        value["edges"]
    );
    // `Registry.register(..)` — an `object` used as its own receiver.
    assert!(
        has_edge(&value, "app.viaObject", "lib.Registry.register"),
        "expected viaObject -> lib.Registry.register: {}",
        value["edges"]
    );
    // `Counter(1)` is a construction, so it references the class. Kotlin's
    // primary constructor is a *synthetic* `Counter.Counter` unit, and the
    // workspace catalog carries no synthetic declarations, so the class is the
    // node a constructor call can land on.
    assert!(
        has_edge(&value, "app.viaConstructor", "lib.Counter"),
        "expected viaConstructor -> lib.Counter: {}",
        value["edges"]
    );
}

#[test]
fn receiver_typing_is_type_based_not_name_based() {
    let value = usage_graph();

    // `Consumer` declares its own `greet`, so a call through a Consumer-typed
    // receiver must land there and *not* on `lib.Base.greet`. Both halves matter:
    // resolving by name alone would produce the wrong edge and hide the right one.
    assert!(
        has_edge(&value, "app.viaWrongReceiver", "app.Consumer.greet"),
        "expected viaWrongReceiver -> app.Consumer.greet: {}",
        value["edges"]
    );
    assert!(
        !has_edge(&value, "app.viaWrongReceiver", "lib.Base.greet"),
        "viaWrongReceiver must not edge to lib.Base.greet: {}",
        value["edges"]
    );
}

#[test]
fn resolves_inherited_and_overridden_members_to_their_declarations() {
    let value = usage_graph();

    // `Derived` does not declare `helper`; the call binds to the ancestor that
    // does, so the edge names `lib.Base.helper` and not a `lib.Derived.helper`
    // that no declaration has.
    assert!(
        has_edge(&value, "app.viaInherited", "lib.Base.helper"),
        "expected viaInherited -> lib.Base.helper: {}",
        value["edges"]
    );
    // `Derived` *does* redeclare `greet`, so a Derived-typed receiver binds to
    // the override rather than to what it overrides.
    assert!(
        has_edge(&value, "app.viaOverride", "lib.Derived.greet"),
        "expected viaOverride -> lib.Derived.greet: {}",
        value["edges"]
    );
    assert!(
        !has_edge(&value, "app.viaOverride", "lib.Base.greet"),
        "viaOverride must not edge to lib.Base.greet: {}",
        value["edges"]
    );
}

#[test]
fn resolves_extension_calls_and_top_level_calls_to_their_declarations() {
    let value = usage_graph();

    // An extension is declared outside the type it extends, so it is reached
    // through the receiver's type but is never one of its members.
    assert!(
        has_edge(&value, "app.viaExtension", "lib.shout"),
        "expected viaExtension -> lib.shout: {}",
        value["edges"]
    );
    // A Kotlin top-level callable has no owner at all; it is named through the
    // file's own scope, here through an explicit import.
    assert!(
        has_edge(&value, "app.viaTopLevel", "lib.topLevelHelper"),
        "expected viaTopLevel -> lib.topLevelHelper: {}",
        value["edges"]
    );
}

#[test]
fn a_property_read_references_its_owner_and_invents_no_property_node() {
    let value = usage_graph();

    // `viaProperty(counter: Counter)` reads `counter.count`. The workspace graph
    // is a class-and-callable graph — no language contributes field nodes — so
    // the observable reference is to the owning type, and the property read must
    // not fabricate a `lib.Counter.count` endpoint that is not a node. (The
    // property reference itself is a `scan_usages` question, covered by
    // `usages_kotlin_graph_test`.)
    assert!(
        has_edge(&value, "app.viaProperty", "lib.Counter"),
        "expected viaProperty -> lib.Counter: {}",
        value["edges"]
    );
    assert!(
        inbound(&value, "lib.Counter.count").is_empty(),
        "a field must not become a usage-graph endpoint: {:?}",
        inbound(&value, "lib.Counter.count")
    );
}

#[test]
fn same_owner_calls_do_not_create_proven_inbound_edges() {
    let value = usage_graph();

    // `inner()` is called only from its own class, through implicit `this`. Under
    // the uniform #1014 facet B / #1138 policy that is recorded as unproven
    // inbound, never a proven edge — so a private helper does not look externally
    // used, and is not confidently dead either.
    assert!(
        inbound(&value, "app.SelfCaller.inner").is_empty(),
        "same-owner call must not be a proven inbound edge: {:?}",
        inbound(&value, "app.SelfCaller.inner")
    );
}

#[test]
fn a_declaration_used_only_from_kotlin_has_inbound_edges() {
    let value = usage_graph();

    // The dead-code-adjacent property: before this milestone every Kotlin
    // declaration had zero inbound edges, because Kotlin source contributed none.
    assert!(
        !inbound(&value, "lib.Base.greet").is_empty(),
        "lib.Base.greet must have inbound edges: {}",
        value["edges"]
    );
    // …and a member nothing calls still has none, so "no inbound edges" stays
    // meaningful rather than becoming universally true.
    assert!(
        inbound(&value, "lib.Base.unused").is_empty(),
        "lib.Base.unused must have no inbound edges: {:?}",
        inbound(&value, "lib.Base.unused")
    );
}

#[test]
fn every_edge_endpoint_is_a_node() {
    assert_every_edge_endpoint_is_a_node(&usage_graph());
}

#[test]
fn no_self_edges() {
    let value = usage_graph();
    assert!(
        !value["edges"]
            .as_array()
            .expect("edges array")
            .iter()
            .any(|edge| edge["from"] == edge["to"]),
        "self references must not appear as edges: {}",
        value["edges"]
    );
}
