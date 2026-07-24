---
title: Receiver Traversal
description: Trace bounded receiver values and exact member targets with query_code.
---

Receiver-bearing structural sites can expose Bifrost's bounded, demand-driven receiver facts. The three terminal steps preserve uncertainty explicitly:

- `points_to` describes the value denoted by an expression.
- `receiver_targets` describes the possible receiver values at a call or member access.
- `member_targets` returns exact indexed member declarations selected through those receiver values.

Every analyzed input produces a `receiver_analysis` row. Read its `outcome` before using its candidates: `precise`, `ambiguous`, `unknown`, `unsupported`, and `exceeded_budget` are distinct states. This is not whole-program points-to, general alias analysis, path-sensitive control flow, taint, or data-flow analysis.

> Last verified end to end: 2026-07-23 (`query_code` schema version 2).

## Fixture

All examples on this page execute against this file.

<!-- code-query-fixture:receiver.ts -->
```typescript
class Service {
  run() {}
}

class Other {
  run() {}
}

function makeService() {
  return new Service();
}

function consume(value: Service) {
  value.run();
}

export function caller(flag: boolean) {
  const direct = new Service();
  direct.run();

  const factory = makeService();
  factory.run();

  const ambiguous = flag ? new Service() : new Other();
  ambiguous.run();

  consume(new Service());
}
```

## Direct Allocation

`capture` on a receiver step is valid only when the preceding domain is a structural match, and the name must identify a positive capture in the pattern. Every unique range bound to that capture is analyzed.

<!-- code-query-case:allocation:rql -->
```lisp
(points-to :capture receiver
  (language typescript
    (call :callee "run"
      :receiver (identifier :name "direct" :capture "receiver"))))
```

<!-- code-query-case:allocation:json -->
```json
{"languages":["typescript"],"match":{"kind":"call","callee":{"name":"run"},"receiver":{"kind":"identifier","name":"direct","capture":"receiver"}},"steps":[{"op":"points_to","capture":"receiver"}]}
```

<!-- code-query-case:allocation:expected -->
```json
{"results":[{"analysis_kind":"points_to","capture":"receiver","input_kind":"identifier","language":"typescript","outcome":"precise","path":"receiver.ts","provenance":[{"seed":{"end_line":19,"kind":"call","path":"receiver.ts","result_type":"structural_match","start_line":19},"steps":[{"op":"points_to","result":{"analysis_kind":"points_to","capture":"receiver","outcome":"precise","path":"receiver.ts","range":{"end_column":9,"end_line":19,"start_column":3,"start_line":19},"result_type":"receiver_analysis"}}]}],"range":{"end_column":9,"end_line":19,"start_column":3,"start_line":19},"result_type":"receiver_analysis","text":"direct","values":[{"allocation_site":{"path":"receiver.ts","range":{"end_column":31,"end_line":18,"start_column":18,"start_line":18}},"receiver_value_kind":"allocation_site","type_declaration":{"end_line":3,"fq_name":"Service","kind":"class","language":"typescript","path":"receiver.ts","signature":"class Service {","start_line":1}}]}],"truncated":false}
```

## Factory Return Provenance

A factory result retains both the exact factory declaration and the nested value it returned. Here that nested value terminates at the exact `Service` allocation site.

<!-- code-query-case:factory:rql -->
```lisp
(points-to :capture receiver
  (language typescript
    (call :callee "run"
      :receiver (identifier :name "factory" :capture "receiver"))))
```

<!-- code-query-case:factory:json -->
```json
{"languages":["typescript"],"match":{"kind":"call","callee":{"name":"run"},"receiver":{"kind":"identifier","name":"factory","capture":"receiver"}},"steps":[{"op":"points_to","capture":"receiver"}]}
```

<!-- code-query-case:factory:expected -->
```json
{"results":[{"analysis_kind":"points_to","capture":"receiver","input_kind":"identifier","language":"typescript","outcome":"precise","path":"receiver.ts","provenance":[{"seed":{"end_line":22,"kind":"call","path":"receiver.ts","result_type":"structural_match","start_line":22},"steps":[{"op":"points_to","result":{"analysis_kind":"points_to","capture":"receiver","outcome":"precise","path":"receiver.ts","range":{"end_column":10,"end_line":22,"start_column":3,"start_line":22},"result_type":"receiver_analysis"}}]}],"range":{"end_column":10,"end_line":22,"start_column":3,"start_line":22},"result_type":"receiver_analysis","text":"factory","values":[{"factory":{"end_line":11,"fq_name":"makeService","kind":"function","language":"typescript","path":"receiver.ts","signature":"function makeService() { ... }","start_line":9},"receiver_value_kind":"factory_return","returned_value":{"allocation_site":{"path":"receiver.ts","range":{"end_column":23,"end_line":10,"start_column":10,"start_line":10}},"receiver_value_kind":"allocation_site","type_declaration":{"end_line":3,"fq_name":"Service","kind":"class","language":"typescript","path":"receiver.ts","signature":"class Service {","start_line":1}}}]}],"truncated":false}
```

## Exact Member Target, Not Same-Name Guessing

Both classes declare `run`, but the direct receiver is a `Service`. `member_targets` returns only that owner's declaration; it never falls back to an unrelated same-name member.

<!-- code-query-case:same-name-member:rql -->
```lisp
(member-targets
  (language typescript
    (call :callee "run" :receiver "direct")))
```

<!-- code-query-case:same-name-member:json -->
```json
{"languages":["typescript"],"match":{"kind":"call","callee":{"name":"run"},"receiver":{"name":"direct"}},"steps":[{"op":"member_targets"}]}
```

<!-- code-query-case:same-name-member:expected -->
```json
{"results":[{"analysis_kind":"member_targets","input_kind":"receiver","language":"typescript","member_targets":[{"end_line":2,"fq_name":"Service.run","kind":"function","language":"typescript","path":"receiver.ts","signature":"run() { ... }","start_line":2}],"outcome":"precise","path":"receiver.ts","provenance":[{"seed":{"end_line":19,"kind":"call","path":"receiver.ts","result_type":"structural_match","start_line":19},"steps":[{"op":"member_targets","result":{"analysis_kind":"member_targets","outcome":"precise","path":"receiver.ts","range":{"end_column":9,"end_line":19,"start_column":3,"start_line":19},"result_type":"receiver_analysis"}}]}],"range":{"end_column":9,"end_line":19,"start_column":3,"start_line":19},"result_type":"receiver_analysis","text":"direct"}],"truncated":false}
```

## Bounded Ambiguity

The conditional initializer has two bounded candidates. The row remains `ambiguous` and retains both allocation/type candidates; neither is silently upgraded to precise.

<!-- code-query-case:ambiguity:rql -->
```lisp
(receiver-targets
  (language typescript
    (call :callee "run" :receiver "ambiguous")))
```

<!-- code-query-case:ambiguity:json -->
```json
{"languages":["typescript"],"match":{"kind":"call","callee":{"name":"run"},"receiver":{"name":"ambiguous"}},"steps":[{"op":"receiver_targets"}]}
```

<!-- code-query-case:ambiguity:expected -->
```json
{"results":[{"analysis_kind":"receiver_targets","input_kind":"identifier","language":"typescript","outcome":"ambiguous","path":"receiver.ts","provenance":[{"seed":{"end_line":25,"kind":"call","path":"receiver.ts","result_type":"structural_match","start_line":25},"steps":[{"op":"receiver_targets","result":{"analysis_kind":"receiver_targets","outcome":"ambiguous","path":"receiver.ts","range":{"end_column":12,"end_line":25,"start_column":3,"start_line":25},"result_type":"receiver_analysis"}}]}],"range":{"end_column":12,"end_line":25,"start_column":3,"start_line":25},"result_type":"receiver_analysis","text":"ambiguous","values":[{"allocation_site":{"path":"receiver.ts","range":{"end_column":41,"end_line":24,"start_column":28,"start_line":24}},"receiver_value_kind":"allocation_site","type_declaration":{"end_line":3,"fq_name":"Service","kind":"class","language":"typescript","path":"receiver.ts","signature":"class Service {","start_line":1}},{"allocation_site":{"path":"receiver.ts","range":{"end_column":55,"end_line":24,"start_column":44,"start_line":24}},"receiver_value_kind":"allocation_site","type_declaration":{"end_line":7,"fq_name":"Other","kind":"class","language":"typescript","path":"receiver.ts","signature":"class Other {","start_line":5}}]}],"truncated":false}
```

## Compose From A Reference Site

`references_of` produces exact reference-site rows. `member_targets` can consume them and reuses the same receiver-qualified member resolution used by definition and usage analysis.

<!-- code-query-case:reference-member:rql -->
```lisp
(member-targets
  (references-of :proof proven
    (enclosing-decl
      (language typescript
        (inside (class :name "Service") (method :name "run"))))))
```

<!-- code-query-case:reference-member:json -->
```json
{"languages":["typescript"],"match":{"kind":"method","name":"run"},"inside":{"kind":"class","name":"Service"},"steps":[{"op":"enclosing_decl"},{"op":"references_of","proof":"proven"},{"op":"member_targets"}]}
```

<!-- code-query-case:reference-member:expected -->
```json
{"results":[{"analysis_kind":"member_targets","input_kind":"receiver","language":"typescript","member_targets":[{"end_line":2,"fq_name":"Service.run","kind":"function","language":"typescript","path":"receiver.ts","signature":"run() { ... }","start_line":2}],"outcome":"precise","path":"receiver.ts","provenance":[{"seed":{"end_line":2,"kind":"method","path":"receiver.ts","result_type":"structural_match","start_line":2},"steps":[{"op":"enclosing_decl","result":{"end_line":2,"fq_name":"Service.run","kind":"function","path":"receiver.ts","result_type":"declaration","start_line":2}},{"op":"references_of","result":{"path":"receiver.ts","proof":"proven","range":{"end_column":12,"end_line":14,"start_column":9,"start_line":14},"reference_kind":"method_call","result_type":"reference_site","target_fq_name":"Service.run"}},{"op":"member_targets","result":{"analysis_kind":"member_targets","outcome":"precise","path":"receiver.ts","range":{"end_column":8,"end_line":14,"start_column":3,"start_line":14},"result_type":"receiver_analysis"}}]}],"range":{"end_column":8,"end_line":14,"start_column":3,"start_line":14},"result_type":"receiver_analysis","text":"value"},{"analysis_kind":"member_targets","input_kind":"receiver","language":"typescript","member_targets":[{"end_line":2,"fq_name":"Service.run","kind":"function","language":"typescript","path":"receiver.ts","signature":"run() { ... }","start_line":2}],"outcome":"precise","path":"receiver.ts","provenance":[{"seed":{"end_line":2,"kind":"method","path":"receiver.ts","result_type":"structural_match","start_line":2},"steps":[{"op":"enclosing_decl","result":{"end_line":2,"fq_name":"Service.run","kind":"function","path":"receiver.ts","result_type":"declaration","start_line":2}},{"op":"references_of","result":{"path":"receiver.ts","proof":"proven","range":{"end_column":13,"end_line":19,"start_column":10,"start_line":19},"reference_kind":"method_call","result_type":"reference_site","target_fq_name":"Service.run"}},{"op":"member_targets","result":{"analysis_kind":"member_targets","outcome":"precise","path":"receiver.ts","range":{"end_column":9,"end_line":19,"start_column":3,"start_line":19},"result_type":"receiver_analysis"}}]}],"range":{"end_column":9,"end_line":19,"start_column":3,"start_line":19},"result_type":"receiver_analysis","text":"direct"},{"analysis_kind":"member_targets","input_kind":"receiver","language":"typescript","member_targets":[{"end_line":2,"fq_name":"Service.run","kind":"function","language":"typescript","path":"receiver.ts","signature":"run() { ... }","start_line":2}],"outcome":"precise","path":"receiver.ts","provenance":[{"seed":{"end_line":2,"kind":"method","path":"receiver.ts","result_type":"structural_match","start_line":2},"steps":[{"op":"enclosing_decl","result":{"end_line":2,"fq_name":"Service.run","kind":"function","path":"receiver.ts","result_type":"declaration","start_line":2}},{"op":"references_of","result":{"path":"receiver.ts","proof":"proven","range":{"end_column":14,"end_line":22,"start_column":11,"start_line":22},"reference_kind":"method_call","result_type":"reference_site","target_fq_name":"Service.run"}},{"op":"member_targets","result":{"analysis_kind":"member_targets","outcome":"precise","path":"receiver.ts","range":{"end_column":10,"end_line":22,"start_column":3,"start_line":22},"result_type":"receiver_analysis"}}]}],"range":{"end_column":10,"end_line":22,"start_column":3,"start_line":22},"result_type":"receiver_analysis","text":"factory"}],"truncated":false}
```

## Compose From A Call Input

`call_input` preserves the exact expression written for a resolved formal parameter. `points_to` then analyzes that expression without pretending it followed assignments or general interprocedural data flow. Here the exact allocation is retained, while an omitted unresolved call candidate keeps the receiver row `ambiguous` instead of silently claiming whole-program precision.

<!-- code-query-case:call-input:rql -->
```lisp
(points-to
  (call-input :parameter-index 0
    (call-sites-to :proof proven
      (enclosing-decl
        (language typescript (function :name "consume"))))))
```

<!-- code-query-case:call-input:json -->
```json
{"languages":["typescript"],"match":{"kind":"function","name":"consume"},"steps":[{"op":"enclosing_decl"},{"op":"call_sites_to","proof":"proven"},{"op":"call_input","parameter_index":0},{"op":"points_to"}]}
```

<!-- code-query-case:call-input:expected -->
```json
{"diagnostics":[{"code":"call_relation_candidates_omitted","impact":"incomplete","language":"typescript","message":"omitted 1 unresolved call candidate for consume"}],"results":[{"analysis_kind":"points_to","input_kind":"new_expression","language":"typescript","outcome":"ambiguous","path":"receiver.ts","provenance":[{"seed":{"end_line":15,"kind":"function","path":"receiver.ts","result_type":"structural_match","start_line":13},"steps":[{"op":"enclosing_decl","result":{"end_line":15,"fq_name":"consume","kind":"function","path":"receiver.ts","result_type":"declaration","start_line":13}},{"op":"call_sites_to","result":{"callee_fq_name":"consume","caller_fq_name":"caller","path":"receiver.ts","proof":"proven","range":{"end_column":25,"end_line":27,"start_column":3,"start_line":27},"result_type":"call_site"}},{"op":"call_input","result":{"input_kind":"parameter","parameter_index":0,"parameter_name":"value","path":"receiver.ts","range":{"end_column":24,"end_line":27,"start_column":11,"start_line":27},"result_type":"expression_site"}},{"op":"points_to","result":{"analysis_kind":"points_to","outcome":"ambiguous","path":"receiver.ts","range":{"end_column":24,"end_line":27,"start_column":11,"start_line":27},"result_type":"receiver_analysis"}}]}],"range":{"end_column":24,"end_line":27,"start_column":11,"start_line":27},"result_type":"receiver_analysis","text":"new Service()","values":[{"allocation_site":{"path":"receiver.ts","range":{"end_column":24,"end_line":27,"start_column":11,"start_line":27}},"receiver_value_kind":"allocation_site","type_declaration":{"end_line":3,"fq_name":"Service","kind":"class","language":"typescript","path":"receiver.ts","signature":"class Service {","start_line":1}}]}],"truncated":false}
```

## Capability And Safety Boundary

The [Java tutorial](../java/#analyze-a-java-receiver) executes a typed receiver example; this page exercises the same public contract with JavaScript/TypeScript allocation, factory, ambiguity, exact-member, reference-site, and call-input behavior. Those examples illustrate the adapter-neutral contract rather than define its coverage. Each selected adapter contributes structured facts and exact resolver evidence when available; virtual or dynamic dispatch, metaprogramming, unsupported syntax, and source forms without receiver semantics remain explicit uncertainty boundaries rather than masquerading as zero matches.

Candidate-cap truncation and receiver budget exits set top-level `truncated`, identify the exhausted limit, and emit a diagnostic. Ordinary bounded ambiguity does not set `truncated`. For a completeness-sensitive decision, require `truncated: false`, inspect every outcome, reject or account for diagnostics whose `impact` is `incomplete` or `invalid`, and check `provenance_truncated` as described in [Agent Result Safety](/agent-result-safety/).
