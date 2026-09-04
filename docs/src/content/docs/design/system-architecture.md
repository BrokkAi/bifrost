---
title: System Architecture
description: Follow a Bifrost request from an editor or agent through the runtime, analyzers, semantic engines, and store.
---

Editors, agents, CLI clients, and library callers use the same analysis runtime.
Transport stays at the outer edge; orchestration, language knowledge, semantic
engines, and durable storage sit behind it.

![Bifrost is layered from clients and protocol adapters through one runtime into query, policy, flow, and analysis engines backed by language front ends and a SQLite store.](../../../assets/design-system-overview.svg)

## Layer map

### Client and protocol layer

The CLI, Rust library, Python client, MCP server, and LSP server are entry
points. MCP is optimized for tool calls from agents; LSP is optimized for
editor navigation. Shared analysis services decide whether a graph edge is
proven and whether an empty result is complete.

The protocol-neutral runtime owns the shared code-intelligence operations and
their serializable extension boundary. Protocol hosts map requests,
cancellation, and errors onto that runtime. Canonical result data is produced
below the transport boundary, so equivalent operations have the same semantics
whether they arrive over JSON-RPC or MCP.

### Query and policy layer

Rune Query Language (RQL) is the human-oriented authoring frontend for the
canonical typed `CodeQuery` model. The RQL compiler produces a `CodeQuery`.
JSON is its stable machine-facing serialization: MCP clients can supply fields
inline, and `query_file` accepts saved `.rql` queries. Both paths reach the same
typed logical and physical planner. Rust embedders can also construct the model
directly. See
[Query Representations](/code-querying/#query-representations) for the detailed
trade-offs and execution surfaces.

Policies add versioned authoring, endpoint selection, finding construction,
completion rules, and report formats. A structural endpoint match selects a
source or sink. The dataflow executor establishes whether a path connects them.

### Flow layer

The flow crate owns language-neutral value-flow, taint, typestate, type-flow,
and reusable-summary clients. They reuse one bounded interprocedural
call/return engine while retaining separate domains and result contracts. A
taint class, typestate state, and inferred receiver class remain distinct types.

### Analysis layer

The analysis engine coordinates workspace snapshots, language analyzers,
structural indexes, usage resolution, semantic lowering, CFG/ICFG construction,
and semantic-model activation. The multi-analyzer routes each file to the
appropriate language implementation while presenting shared analyzer
capabilities to callers.

### Core and language-knowledge layer

The core crate contains the dependency-free domain model: project files,
languages, code units, structured names and identities, cancellation, compact
IDs, canonical hashing, and cache-database foundations. Language crates depend
on that model and implement language-specific knowledge such as imports,
visibility, hierarchy, declaration extraction, call shapes, and usage
resolution.

Language rules stay in language crates because Java overload applicability,
Rust module routing, C++ macro-aware identity, and Ruby autoload visibility use
different semantics. Typed interfaces let them produce common evidence shapes.
The adapter and resolver boundary is defined in the
[front-end chapter](../identity-and-language-frontends/#shared-syntax-language-specific-semantics).

### Storage layer

The analyzer store is SQLite-backed. It persists content-addressed, queryable
facts and projects them through workspace-generation views. A serialized writer
and bounded reader pool allow writes and snapshot reads to proceed concurrently.
In-memory caches hold complete immutable derived values within explicit byte
budgets. The storage chapter's
[analysis storage layers](../storage-and-cache/#analysis-storage-layers) define
the boundary between those durable, projected, and cached representations.

## Request lifecycle

A typical request follows this sequence:

1. The host binds the request to a workspace generation and cancellation
   token.
2. The query layer validates the operation, limits, and requested capability.
3. The analyzer selects durable facts and current source content by exact
   identity.
4. If the request needs deeper semantics, language adapters materialize
   immutable per-file semantic artifacts and a bounded interprocedural view.
5. A structural executor, usage resolver, or flow client computes evidence
   under the request budget.
6. The runtime canonicalizes results together with execution status, proof,
   completeness, diagnostics, and provenance.
7. The protocol adapter maps that result to its wire format and preserves its
   uncertainty and analysis boundaries.

The workspace generation associates each result with the exact source snapshot
used to compute it. The
[revisioned workspace projections](../storage-and-cache/#revisioned-workspace-projections)
section describes the read-side isolation mechanics.

## Representation lifetimes

| Representation | Typical lifetime | Why |
| --- | --- | --- |
| Parsed declarations and structural rows | Across processes and compatible worktrees | They are the reusable, queryable, content-addressed output of upfront workspace indexing. |
| File semantic artifact | Across requests while its full validity key matches | It is immutable but more expensive and memory-heavy than structural rows. |
| Bounded ICFG snapshot | One solve or retained result | Its dense IDs and expanded contexts are run-local. |
| Complete procedure summary | Across compatible solves within a bounded repository | Its stable semantic identity can replace re-analysis, but only for inputs covered by its validity key. |
| Finding/report | One exact policy, snapshot, and configuration identity | Presentation must refer to the evidence actually solved. |

*Upfront indexing* stops after publishing source-derived declarations and
structural relations. File semantic artifacts, bounded ICFGs, and solver state
are materialized on demand.
[Storage and Cache Strategy](../storage-and-cache/#content-addressed-relational-facts)
shows how those indexed facts are published and reused.

## Dependency boundaries

Dependencies flow upward through the crate structure:

- core contains types that every language can share without importing the main
  analysis engine;
- language crates contain their own semantic knowledge;
- analysis composes core, languages, storage, and semantic lowering;
- flow depends on the semantic-provider contracts from analysis;
- RQL and policy build typed user-facing operations above analysis and flow;
- runtime composes the protocol-neutral product surface; and
- MCP and LSP remain hosts at the outer edge.

The layering keeps ownership explicit. A type belongs in core only if it needs
no analyzer, store, grammar, or language module.

## Local-first service boundary

The shipped service model is local: analysis runs against a client-approved
workspace root and reads local source. Unsaved or mid-refactor code remains
available to the analyzer, and source custody stays within the local trust
boundary. A remote multi-tenant service would require additional decisions
about authentication, resource isolation, cancellation, cache tenancy, and
version negotiation. That deployment model remains a research topic; the
current architecture assumes a local service boundary.

## Cross-cutting invariants

Every subsystem is expected to preserve the same invariants:

- exact identity is structured and source- or resolver-backed;
- source coordinates support identity claims; durable identity requires the
  structured subject behind those coordinates;
- partial positive evidence remains usable; absence claims require
  complete coverage;
- cancellation and budget exhaustion are terminal properties of that request;
- cache publication requires complete, current inputs;
- run-local dense IDs never escape as durable identities.

The [Evidence and Result Contract](../evidence-and-results/) shows how these
invariants appear at the client boundary.
