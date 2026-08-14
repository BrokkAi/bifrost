# brokk-bifrost-rql

Analyzer-independent RQL syntax, schema, typed IR, and validation for
brokk-bifrost.

This crate exists for build-graph relief and abstraction hygiene. It keeps the
RQL parse, validate, and IR boundary independent from analyzer execution.

The release owner must bootstrap this crate on crates.io and configure its
trusted publisher before the next version release.
