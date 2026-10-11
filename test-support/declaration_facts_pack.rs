use serde_json::{Value, json};

pub struct DeclarationFactsPack<'a> {
    pub pack_id: &'a str,
    pub version: &'a str,
    pub producer_name: &'a str,
    pub language: &'a str,
    pub ecosystem: &'a str,
    pub toolchains: Value,
    pub completeness: &'a str,
    pub shard_id: &'a str,
    pub activation: Value,
    pub types: Value,
    pub members: Value,
}

pub fn build(pack: DeclarationFactsPack<'_>) -> Value {
    json!({
        "schema_version": 2,
        "pack_id": pack.pack_id,
        "version": pack.version,
        "producer": { "name": pack.producer_name, "version": "1.0.0" },
        "language": pack.language,
        "ecosystem": pack.ecosystem,
        "compatibility": { "bifrost": "*", "toolchains": pack.toolchains },
        "provenance": { "source": "fixture" },
        "license": "NOASSERTION",
        "completeness": pack.completeness,
        "safety": { "generated_code_only": false, "review_required": false },
        "shards": [{
            "id": pack.shard_id,
            "activation": pack.activation,
            "payload": {
                "kind": "declaration_facts",
                "types": pack.types,
                "members": pack.members,
                "relations": []
            }
        }]
    })
}
