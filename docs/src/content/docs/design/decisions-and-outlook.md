---
title: Decisions and Outlook
description: A public decision record for Bifrost's settled architecture, active directions, research questions, and non-goals.
---

`Current` marks behavior in this release line. `Direction` records intended
work and its readiness criteria. `Research` marks unresolved design questions.
Roadmap labels carry no release dates. Entries link to the subsystem chapters
that describe the current implementation and limits.

## Settled decisions

### Keep one analysis contract below every protocol

**Status: Current.** MCP, LSP, CLI, and library hosts call shared analysis
services. Those services define the canonical result and its proof semantics;
protocol adapters handle transport, lifecycle, and error mapping.

**Trade-off:** Protocol-specific shortcuts are constrained so the same operation
has the same meaning in an editor and an agent.

### Derive exact identity from structure and resolution

**Status: Current.** Parsed nodes and language resolvers provide exact identity
for declarations, calls, formals, receivers, imports, and members. Display
strings, source snippets, regular expressions, and delimiter parsing remain
presentation or discovery data.

**Trade-off:** Bifrost reports ambiguity or unknown when structured evidence
leaves more than one possible target.

### Persist durable facts; materialize expensive semantics on demand

**Status: Current.** The relational store holds queryable declarations and
structural relations. Bifrost builds semantic artifacts, bounded ICFG views,
and solver state for a request, then retains them only under complete validity
keys.

**Trade-off:** The first deep query may have to construct its semantic view.
Ordinary navigation avoids the cost of maintaining every possible dataflow
derivation.

### Key caches by semantic inputs

**Status: Current.** Reuse keys cover content, workspace generation, language
and grammar epochs, adapter and IR semantics, configuration, dependencies, and
active models as applicable. Age has no bearing on validity.

**Trade-off:** Keys and invalidation logic carry more detail. They permit safe
reuse across processes and compatible worktrees.

### Restrict complete caches to complete values

**Status: Current.** Complete caches accept only successful, complete
computations. Cancelled, budget-exhausted, stale, failed, and semantically
partial results remain outside the cache.

**Trade-off:** A later request may repeat partial work. Publishing that work as
complete would give subsequent requests a false completeness claim.

### Put language rules in language crates

**Status: Current.** Language crates implement imports, visibility, overloads,
hierarchy, call shapes, and ecosystem conventions. Shared engines consume their
typed facts and outcomes through common contracts.

**Trade-off:** Each language needs a substantive adapter. Clients can still
handle evidence consistently through the common result contract.

### Use a bounded distributive interprocedural kernel

**Status: Current.** IFDS-family fact propagation and IDE-style edge functions
share an explicit ICFG plus contracts for budgets, termination, path quality,
summaries, and witnesses. Analyses outside the finite distributive domain use a
separately named abstraction.

**Trade-off:** The solver covers a narrower domain than a general abstract
interpreter. That domain has testable rules for behavior, reuse, and
incompleteness.

### Include evidence quality and coverage in results

**Status: Current.** Client-visible results carry proof, completeness,
provenance, work, scope, and termination. An empty partial response does not
support a clean result.

**Trade-off:** Results require more structure than a list of locations. Clients
use those fields to describe the result accurately.

## Active directions

### Compose immutable usage facts

**Status: Direction.** The proposed usage engine stores immutable file-local
resolution material under its content identity. A query composes those facts
for the selected workspace, avoiding a mutable global graph and chains of
parent deltas. See the
[usage-analysis design](../usage-analysis/#persisted-inputs-and-compositional-usage-facts)
for the composition contract and current implementation, and the
[storage direction](../storage-and-cache/#direction-compositional-resolution-fragments)
for the finer-grained cache question. Shipping requires parity with current
resolvers, bounded memory, accurate cancellation and cap reporting, and useful
reuse across linked worktrees.

### Close known semantic gaps

**Status: Direction.** Dataflow conformance tests expose recurring sources of
incomplete results: unresolved dispatch, field identity, destructuring and
unpacking, language hooks, and missing dependency behavior. Each gap needs
structured semantics and positive and near-miss tests. Existing cases remain
incomplete until that support exists. See
[Dataflow Maturity and Limits](../dataflow-engine/#maturity-and-limits) for the
current experimental boundary.

### Persist reusable class-set and procedure knowledge

**Status: Direction.** Complete content-keyed summaries could reduce repeated
receiver, type, and procedure analysis. Shipping them requires stable identity,
dependency closure, complete witness semantics, and safe invalidation. Type-flow
results remain experimental and are often partial or inconclusive on broad
corpora.
[Summary Identity and Reuse](../semantic-models/#summary-identity-and-reuse)
specifies the model-side identity gate, while
[Summary Lifetimes](../dataflow-engine/#summary-lifetimes)
separates authored models from solver reuse.

### Complete incremental policy evaluation

**Status: Direction.** The store already represents policy evaluation units.
The general coordinator still needs to select reusable units, recompute affected
units, and prove parity with a fresh full evaluation. The schema alone does not
provide incremental execution.

### Automate dependency discovery

**Status: Direction.** Automatic dependency discovery and semantic-pack
activation could improve coverage. Every discovered artifact, pack, producer,
compatibility decision, and rejection must remain observable. Activation must
be based on identified dependencies and compatibility evidence.
The current diagnosable pipeline is described under
[Current Boundaries](../semantic-models/#current-boundaries) in the
semantic-model chapter.

### Add stable public analysis capabilities

**Status: Direction.** Typestate and other deeper analyses can enter the
serializable extension API after their identities, limits, capability
negotiation, and completion semantics stabilize. An internal or policy-only
implementation is insufficient for a public extension capability.
The current experimental boundary is summarized under
[Dataflow Maturity and Limits](../dataflow-engine/#maturity-and-limits).

## Research questions

### Remote service deployment

**Status: Research.** A remote MCP or shared analysis service changes the trust
model. The [local-first service boundary](../system-architecture/#local-first-service-boundary)
describes the current baseline. A hosted design still needs explicit policies
for source custody, authentication, tenancy, cache isolation, scheduling,
cancellation, version skew, audit logging, and deletion.

### Richer heap and context precision

**Status: Research.** Heap abstraction, aliases, context selection, and dynamic
dispatch can improve precision, enlarge the state space, and invalidate summary
identities. Candidate designs need independent oracles and measurements on real
corpora. Finding more paths in one fixture is insufficient evidence.

### Concurrency guarantees

**Status: Research.** Structured summaries could support typed concurrency
effects and focused race checks. A "race free" result would need a declared
guarantee boundary for thread creation, synchronization, aliasing, native calls,
and unmodeled code. Positive findings and complete absence claims require
different evidence.

## Non-goals

Bifrost does not currently aim to:

- replace language compilers or claim compiler-complete semantics for every
  valid program;
- persist every expanded interprocedural graph and derivation for every query;
- hide unsupported semantics behind text or name heuristics;
- interpret may-reachability as runtime path feasibility;
- claim equal precision for every language because the adapters share an API;
  or
- turn a deterministic fixture or narrow demonstration into a global accuracy
  or scalability claim.

## Open product questions

1. Should a hosted service remain an explicitly separate product architecture,
   or should the local runtime expose tenancy primitives in anticipation of it?
2. Which analysis capabilities should receive long-term wire compatibility
   first: semantic relations, value flow, typestate, or retained policy
   reports?
3. How much roadmap detail belongs in public docs before a direction has an
   executable acceptance test?
4. Should public architecture snapshots be versioned per release, or should
   this guide always describe only the current release line?

## Discuss or contribute

To propose a direction or describe a missing use case,
[open a feature request](https://github.com/BrokkAi/bifrost/issues/new?template=feature_request.yml).
An observed problem is enough; an implementation proposal is optional. For an
informal discussion, [join the Bifrost Discord](https://discord.gg/geYkWUeH).
