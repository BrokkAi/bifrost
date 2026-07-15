mod common;

use brokk_bifrost::Language;
use common::InlineTestProject;
use common::usage_graph::{assert_every_edge_endpoint_is_a_node, has_edge, usage_graph_at};

#[test]
fn namespace_reexport_alias_emits_canonical_edge() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "proto/modules.py",
            "def define_module():\n    return None\n",
        )
        .file(
            "proto/__init__.py",
            "from .modules import define_module as module\n",
        )
        .file(
            "consumer.py",
            "import proto\n\ndef build():\n    return proto.module()\n",
        )
        .build();

    let value = usage_graph_at(project.root(), "{}");
    assert!(
        has_edge(&value, "consumer.build", "proto.modules.define_module"),
        "re-export alias edge is missing: {}",
        value["edges"]
    );
    assert_every_edge_endpoint_is_a_node(&value);
}
