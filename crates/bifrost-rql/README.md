# brokk-bifrost-rql

RQL syntax, schema, typed IR, planning, execution, and result projection for
brokk-bifrost.

This crate owns the query layer above `brokk-bifrost-analysis` and
`brokk-bifrost-flow`. Workspace execution receives caller-owned analyzer and
flow state explicitly.

Most consumers should depend on the `brokk-bifrost` facade instead.
