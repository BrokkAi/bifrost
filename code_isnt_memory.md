# Code Isn't Memory: A Structural Codebase Index Inside a Coding Agent

**Authors:** Ishaan Bhola, Adithyan Krishnan, Sravanth Kurmala, Mukunda NS  
**Affiliation:** SuperAGI Research  
**arXiv:** 2606.22417v1 [cs.AI], 21 June 2026

> **Transformation note.** This Markdown document is a structured transformation of the original two-column PDF, not a page-faithful facsimile. The text has been placed into linear reading order, headings and tables have been converted to Markdown, mathematical definitions and pseudocode have been normalized, and the original figures and graphs have been replaced with explicit prose descriptions that communicate their main point.

## Abstract

Coding agents now interleave LLMs with retrieval over the working repository, and retrieval implementations vary widely across deployed harnesses. Inside a fixed coding-agent harness on a fixed model, does adding a structural codebase index actually change cost or resolve? We ran three arms—the harness with the index, the same harness without it, and an agentic-grep comparator—on SWE-PolyBench Verified and SWE-bench Pro with Claude Opus 4.7 held fixed throughout, across three seeds, inside a leak-audited per-task sandbox.

The within-harness ablation produces a large localization gain and a statistically separated resolve gain, with no cost penalty per cell and lower cost per solve. The cross-harness check shows that the index does not regress against an agentic-grep baseline on resolve or localization, again at no cost penalty. We release the per-cell exclusion ledger, the leak-audit script, the localization extractor, and the results database.

The deployment question for a structural codebase index is thus not whether it is too expensive to run—across seeds, the index lands at a lower dollars-per-solved rate than agentic grep—but whether the workload includes multi-file changes where structural ranking pays off.

**Keywords:** coding agents, code retrieval, structural codebase index, causal ablation, SWE-bench.

**Code and data:** https://github.com/TransformerOptimus/supercoder-eval

## 1. Introduction

Coding agents now interleave LLMs with retrieval over the working repository, and retrieval implementations vary widely across deployed harnesses. The implementations span a spectrum: agentic grep over the working copy, file-dependency repository maps, semantic and graph search, and structural codebase indices built once per repository (§2). Inside a fixed coding-agent harness on a fixed model, does adding a structural codebase index actually change cost or resolve?

We answer the question for open-source harnesses with the model held fixed—Claude Opus 4.7 (§4.2). Closed-source harnesses such as Claude Code, Cursor, and Windsurf are out of scope by design. The experimental design isolates the index causally by toggling it on and off inside one harness while everything else stays identical, and cross-checks the result against an agentic-grep comparator (§4.1).

The field has not had a clean answer because controlled measurements are scarce. Most prior work either compares whole harnesses, where retrieval is confounded with prompt, tool surface, and control loop, or evaluates retrieval components in isolation against acc@k, without the downstream agentic loop that turns ranking into a fix. The question of whether “grep is all you need” has recently been asked in the agentic-search literature for memory-style document retrieval [2], with grep favored over vector retrieval. We ask the code-task counterpart, where the candidate beyond grep is not a vector index but a structural codebase index combining semantic, lexical, and call-graph retrieval.

A structural codebase index is also expensive to build and operate, so if the resolve gain is small and the cost premium is large, the index does not pay for itself in deployment. The integrity bar for benchmark evaluation has risen in parallel: recent audits documented solution leakage in issue text [3], memorization of in-benchmark repositories [4], and substantial score inflation from formal issue text relative to realistic user phrasing [5]. Any positive result therefore needs to survive a leak audit before it counts.

Three arms ran against the same SWE-PolyBench Verified and SWE-bench Pro public instances: 91 instances across Go, Java, and Python, with Claude Opus 4.7 fixed throughout, across three seeds.

- **SC-ON:** the SuperCoder [6] harness with the structural index enabled.
- **SC-OFF:** the same harness with the two context-engine tools removed and every other component identical.
- **OpenCode:** an agentic-grep comparator [7].

Every cell ran inside a hardened per-task sandbox with a fail-closed git scrub and a post-run leak audit (§5). On the causal within-harness ablation (§6.2), the index moves View B acc@5 from 44.3% to 84.5% across seeds (paired Wilcoxon, *p* < 0.0001) and resolve from 41.9% to 50.4% (paired Wilcoxon, *p* = 0.003). It also yields lower cost per solve with a statistically null per-cell cost difference.

On the cross-harness validity check (§6.1), SC-ON matches or modestly favors OpenCode on resolve—50.4% versus 45.3% mean, paired Wilcoxon *p* = 0.087—and on View B acc@5—84.5% versus 75.3% mean, paired Wilcoxon *p* = 0.080—at no cost penalty. The structural codebase index does not merely duplicate behavior that competent agentic grep already reaches; at minimum, it does not regress the agent.

We report the first leak-audited, model-controlled, causal ablation of a shipped structural codebase index inside a coding-agent harness, paired with a cross-harness validity check against an agentic-grep comparator. The result reframes the deployment question from “is a structural codebase index too expensive to run alongside agentic grep?”—on these benchmarks, the answer is no: $2.30 mean across seeds against OpenCode's $2.92, favorable on dollars per solved—to “does the workload include multi-file changes where structural ranking pays off?” (§7).

Released alongside the paper are the per-cell exclusion ledger (§5.3), the leak-audit script, the dual-view localization extractor, and the full results database, so every number in §6 is reproducible from the released artifacts.

## 2. Related Work

### Coding-agent harnesses

SWE-agent [8] introduced the agent-computer-interface framing on top of a single-LLM control loop. OpenHands [9], formerly OpenDevin, generalized the platform with sandboxed execution and multi-agent coordination. Aider [10] drives file-level edits over a local git repository with a dependency-ranked repository map. AutoCodeRover [11] pairs LLM reasoning with AST-aware code search and spectrum-based fault localization. OpenCode [7] is the model-agnostic open-source terminal agent used as the cross-harness comparator (§3.3).

SuperCoder, the harness studied here (§3.1), shares the parallel-tool-dispatch loop posture with these systems but ships a structural codebase index as a first-class tool, which prior measured harnesses do not. SWE-agent is excluded from the comparator set because its agent-computer-interface pipeline was used in SWE-bench's construction, creating circularity for an evaluation on SWE-bench-family tasks. Closed-source harnesses—Claude Code, Cursor, and Windsurf—are out of scope by design; this study fixes the model (§4.2) and varies the open-source harness configuration around it.

### Retrieval approaches for code agents

Four approach types appear in recent literature.

**Agentic grep and read** drives OpenCode [7] and similar terminal-loop agents that call ripgrep over the working copy; there is no structural codebase index. Sen et al. [2] contrast grep with vector retrieval inside agentic loops on the LongMemEval memory-retrieval benchmark, with grep favored. Their setting is non-code and the alternative is dense retrieval, not a structural codebase index, but the framing—does grep suffice inside an agentic harness?—is the closest prior work to ours.

**Repository-level retrieval and planning** predates the agent-harness wave. RepoCoder [12] iteratively retrieves over the whole repository for code completion, and CodePlan [13] stages multi-file edits as a planned sequence of repository-wide operations; neither is built as an agent loop.

**File-dependency repository maps**, exemplified by Aider's PageRank-ranked repository map [10], surface candidate files by import and reference structure but do not index symbol-level semantics.

**Semantic and graph search** combines code-chunk embeddings with typed repository graphs. LocAgent [14] equips an LLM agent with graph-search tools over a heterogeneous code graph. RepoGraph [15] plugs a repository-wide code graph into SWE-agent and AutoCodeRover. The Code Graph Model line [16] integrates the graph directly into an LLM's attention through an adapter. Agentless [17] reaches comparable SWE-bench-Lite scores with a non-agentic three-phase localization-and-repair pipeline.

Structural codebase indices have been adopted in commercial coding-agent stacks; this paper provides the first leak-audited, model-controlled causal ablation of one inside an open-source harness (§6.2).

### Localization metrics for code agents

LocAgent [14] and Agentless [17] report file-level acc@k as the primary localization metric. The field has been moving toward stage-decomposed trajectory metrics: TRAJEVAL [18] decomposes agent trajectories into search, read, and edit phases with per-stage precision and recall, and SWE-Explore [19] isolates repository exploration as a subtask with coverage and ranking metrics against trajectory-derived ground truth.

The paper's View B (§4.7, §6.1) follows the same direction: it strips engine-result paths from the surfaced set so that an SC-ON acc@k counts the same kind of agent-targeted surface as an OpenCode acc@k. The paper does not propose a new localization metric; it adopts the field-trend rule and applies it uniformly across arms.

### SWE-bench family and benchmark integrity

SWE-bench [20] introduced the canonical 2,294-issue Python benchmark. SWE-bench Verified [21] released a 500-issue human-screened subset. Two benchmark-expansion lines extend coverage: SWE-PolyBench [22] is a multi-language SWE-bench-style benchmark with a Verified subset, and SWE-bench Pro [23] provides a harder long-horizon set. This study uses the Verified subset of SWE-PolyBench and the public subset of SWE-bench Pro (§4.3).

Three integrity audits motivate the hardening protocol. SWE-bench+ [3] documented solution leakage in issue text and weak-test pass-throughs in the original SWE-bench. The SWE-bench Illusion paper [4] showed that strong scores partly reflect memorization of in-benchmark repositories. Garg et al. [5] mutate formal GitHub-issue specifications into realistic user-style queries derived from chat-agent telemetry and report capability overestimation above 50% for some models on public benchmarks—a phrasing and ecological-validity threat that detect-and-exclude hardening does not address.

The per-cell scrub, fail-closed gate, and S1 reviewer pass in §5 sit in this audit tradition. The public exclusion ledger (§5.3) extends it by releasing per-cell evidence for every dropped cell.

## 3. System

This section describes the studied subject: the SuperCoder coding-agent harness, the context engine that the ON/OFF arms ablate, and the OpenCode comparator used in the cross-harness arm.

### 3.1. SuperCoder harness

SuperCoder [6] is a coding agent built around a single-LLM control loop. The shipped binary supports three modes—Ask, Plan, and Coding. The evaluation runs in Coding mode, the only mode that may write files or execute shell commands, so all mechanics below refer to the Coding-mode loop. A provider gateway sits in front of the LLM client and captures token-level cost per turn uniformly across arms (§4.5).

Each turn assembles a prompt—system instructions, tool schema, and message history—and issues a single LLM call. If the model emits tool calls, the harness dispatches them, awaits results, and appends them to the message history; if it emits text with no tool calls, the loop terminates. The reasoning-and-acting posture follows ReAct [24], and the tool-call interface follows the function-calling line introduced by Toolformer [25]. Multiple tool calls in a single response are executed in parallel.

If the rolling token count exceeds a threshold, the harness compacts the message history by summarizing older turns. The compaction step is disclosed for reproducibility but is not load-bearing for the ablation. The loop terminates when:

1. the model emits no tool calls;
2. a configured per-cell turn budget is exhausted; or
3. the 30-minute per-cell wall-clock cap (§4.5) elapses.

The agent calls a fixed tool set: `read`, `write`, `edit`, `bash`, `git`, `grep`, and `glob`, plus task-management tools (`todo_write`, `apply_patch`). All are identical across SC-ON and SC-OFF. The two context-engine tools, `codebase_search` and `codebase_graph`, are available only in SC-ON; SC-OFF removes those two tools from the schema and changes nothing else (§3.2).

### 3.2. Context engine

The context engine is a separate service that the agent calls through two tools. It maintains a per-repository index built once on first contact and updated incrementally on subsequent runs through Merkle-tree diffs over the working copy. A source edit therefore invalidates and re-indexes only affected chunks rather than the whole repository.

Each cell in this study starts from a fresh sandbox, so every arm exercises the build path. The incremental-update path is part of the engine but is not load-bearing in the run. The index has three components:

- a vector index of code-chunk embeddings for semantic similarity;
- a graph index of definitions and call edges for structural reachability; and
- a lexical BM25 index of identifiers and tokens for exact-match recall.

Index construction begins with tree-sitter parsing per source file. Definitions, references, and call edges are extracted from the resulting AST and chunked for embedding.

#### Figure 1 — Context-engine pipeline, transformed into text

The original figure is a flow diagram with two stages.

**Indexing stage, run once per repository and then incrementally:** repository source files are parsed with tree-sitter into an AST per file. An extractor collects symbols, identifiers, definitions, references, and caller/callee edges. Code is chunked and embedded. These outputs populate three parallel indices: lexical BM25, a call graph, and a semantic vector index. Later repository changes are handled through Merkle-diff updates rather than full re-indexing.

**Retrieval stage, run on every agent call:** the agent invokes `codebase_search` or `codebase_graph`. Hybrid retrieval queries the three indices, fuses and reranks the hits, removes duplicates, and returns ranked paths, snippets, and scores.

**Main point:** the system separates an up-front structural indexing pass from a lightweight per-query fusion stage, allowing the agent to retrieve semantically related code, exact identifier matches, and graph-connected symbols through one ranked interface.

The components are named at the level supported by the public evaluation repository (§5.3). The backend service that hosts the three indices is internal and not part of the released artifact.

#### Agent-facing tools

`codebase_search` takes a natural-language query plus a retrieval strategy—vector, lexical, graph, or hybrid—and returns a ranked list of code chunks. Each result carries a file path, snippet, relevance score, and the index that produced it. A local overlay drops paths the agent has deleted and flags stale ones.

`codebase_graph` takes a symbol and traverses the call-graph index, returning callers and callees grouped by direction. Each result includes the defining file path and distance from the query node.

#### ON versus OFF concretely

SC-ON exposes both `codebase_search` and `codebase_graph` alongside the file-I/O, shell, and search tools listed in §3.1. SC-OFF removes exactly those two tools from the schema and leaves everything else identical: the rest of the tool set, the model, the prompt template, the sandbox, and the scorer (§4.1).

The toggle is the headless runner's command-line flag for the engine endpoint: present invokes SC-ON; absent invokes SC-OFF. The ablation surface is therefore “with versus without the two engine tools,” and the resolve, localization, and cost consequences are reported in §6.2.

### 3.3. Comparator: OpenCode

OpenCode [7] is an open-source coding agent with a single-LLM control loop, parallel tool dispatch, and a fixed tool set built around `rg` (ripgrep), `read`, `glob`, and `bash`. It has no structural codebase index, embedding-based search, or precomputed call graph.

In the evaluation, OpenCode runs in the same per-task container as the two SuperCoder arms, with Claude Opus 4.7 and the same 30-minute wall-clock cap (§4.5). The headline cross-harness comparison appears in §6.1.

## 4. Experimental Design

This section defines the arms, model, benchmarks, run scope, sandbox and cost-capture infrastructure, metrics, localization-view extraction rule, statistical methods, and narrowed pilot. §6 uses these definitions directly.

### 4.1. Arms

The study compares three arms on the same instance set:

- **SC-ON:** SuperCoder with the context engine's tools available.
- **SC-OFF:** the same harness and prompts, with `codebase_search` and `codebase_graph` removed from the tool set.
- **OpenCode:** an independent open-source harness whose retrieval is built around ripgrep and file reads, with no structural index.

The only change between SC-ON and SC-OFF is the engine tool set, which gives the ablation its causal interpretation. The cross-harness comparison against OpenCode tests whether SC-ON's behavior is reproducible by an alternative open-source harness running the same model.

Across all three arms, the study holds the model—Claude Opus 4.7—the per-task sandbox image, the scorer, and the 30-minute wall-clock cap fixed. No turn or dollar cap is enforced. Each arm runs three seeds.

### 4.2. Model

All three arms run Claude Opus 4.7 (`claude-opus-4-7`) across three seeds. Fixing the model removes capability as a moving part, so any cross-harness difference must come from the harness or its retrieval, not from a stronger backbone. Single-model scope is a limitation acknowledged in §5 and §7; the control trade-off is intentional.

### 4.3. Benchmarks

The instance set draws from two public benchmarks:

- SWE-PolyBench Verified [22], which contributes multi-language coverage in Go, Java, and Python; and
- SWE-bench Pro [23], which contributes longer-context Python tasks.

Both descend from the SWE-bench family [21]. SWE-agent and its trajectories are not used as a comparator because of SWE-agent's role in benchmark construction; the open-source harness comparator is OpenCode [7].

### 4.4. Run scope

The study runs on 91 instances across three languages: 34 Go, 20 Java, and 37 Python. JavaScript and TypeScript are not covered. The run uses three seeds, pass@1 per seed. Statistics are reported as the mean of seed means, with across-seed standard deviation as a variance estimate; seed-variance context follows [26].

#### Table I — Metric definitions

| Metric | Definition |
|---|---|
| Resolve | `1[F2P_pass = F2P_total > 0 AND P2P_pass = P2P_total]` |
| $/cell | Mean per-cell `cost_usd` over legitimate cells, per arm |
| $/solved | Sum of cost over legitimate cells divided by number of legitimate resolved cells, per arm |
| Turns | Tool calls per cell |
| Tokens | LLM input plus output tokens per cell |
| acc@k | `1[|surfaced_1:k ∩ gold| > 0]` |
| recall@k | `|surfaced_1:k ∩ gold| / |gold|` |
| First-gold rank | `min{i : surfaced_i ∈ gold}`; 1-indexed; undefined if there is no match |

Resolve is the public database's `resolved` column, sourced from upstream benchmark scorers. F2P denotes fail-to-pass tests; P2P denotes pass-to-pass tests. Localization is computed under View B (§4.7). Effort and cost are per-cell means on legitimate cells.

#### Paired-n denominators

§6 uses three paired-n values, each with a specific meaning.

- The **triple-intersection set** contains instances on which all three arms produced a legitimate cell (*n* = 75). It is used for descriptive cross-arm context where every row of a table must refer to the same instances.
- Pairwise significance tests use pairwise denominators, because dropping instances that are legitimate in two arms simply because the third arm failed would waste paired signal.
- The pairwise denominators are 80 for SC-ON versus SC-OFF and 78 for SC-ON versus OpenCode.

Every paired test in §6 cites its applicable *n*.

### 4.5. Sandbox and cost capture

Each cell ran inside a per-task isolated container with a uniform image across arms, on an internal sandbox backend. The backend's configurations and image specification are not part of the public release.

A unified provider gateway captured token-level cost on every LLM call, so $/cell and $/solved use the same accounting for all three arms. Per-cell `cost_usd`, `total_cost_usd`, `tokens_total`, and `wall_clock_secs` are released in the public database.

The 30-minute wall-clock cap fired on two cells in the released set: one SC-OFF cell and one OpenCode cell. SC-ON's longest legitimate cell ran 19 minutes. The reproducibility kit lives under `data/`. Per-cell patches, per-trace JSON, prompts, and sandbox image references are held back because they include licensed repository source and internal harness configuration.

Resolve is the public database's `resolved` column, sourced from upstream benchmark scorers. $/cell, $/solved, turns, tokens, and wall-clock are released per cell.

### 4.6. Metrics

The primary outcome is resolve. Supporting outcomes are localization, effort, and cost. Table I gives the formal definitions. Localization is reported under View B by default (§4.7); effort and cost metrics are per-cell means on legitimate cells from the unified provider gateway (§4.5).

### 4.7. Localization views

The study scores localization under two views and reports under one.

**View A, the legacy rule,** counts every path the agent saw as a file the agent reached, including candidate paths returned by engine result lists.

**View B, agent-targeted,** removes paths whose only provenance is an engine result list while keeping the engine's natural-language query arguments. The rationale is that an engine result list is a pointer, not an arrival: the agent must choose to grep, read, or edit a candidate for that path to enter its actual trajectory. Treating a returned list as a set of files reached would credit SC-ON for being shown a path while crediting OpenCode only after it greps one, inflating surfaced sets for the arm whose engine emits such lists.

#### Algorithm 1 — Localization extraction

**Input:** trace `T`, a sequence of events `(tool_call_id, tool, role, paths)`, where `role ∈ {ARGS, RESULT}`.  
**Output:** `surfaced ⊆ files`.  
**Engine tools:** `E = {codebase_search, codebase_graph}`.

```text
function SurfaceViewA(T):
    S = empty set
    for (tool_call_id, tool, role, paths) in T:
        S = S union paths        # every surfaced path counts
    return S

function SurfaceViewB(T):
    S = empty set
    for (tool_call_id, tool, role, paths) in T:
        if not (tool in E and role == RESULT):
            S = S union paths    # skip engine-result paths; keep engine arguments
    return S
```

Mechanically, the extractor tracks the `tool_call_id` of every surfaced path and drops the path if and only if its only provenance is a `codebase_search` or `codebase_graph` result token. View A and View B differ in exactly one condition. The rule is applied uniformly to all arms. SC-OFF and OpenCode emit no engine calls, so View B is a strict no-op for them and only SC-ON's numbers move.

View B is the paper's primary view because stage-decomposed trajectory metrics extend the file-level acc@k posture of LocAgent [14] and Agentless [17] to mixed-action trajectories—the direction the field has been moving [18, 19]. The exact algorithm and the fallback for missing `tool_call_id` are implemented in `scoring/localization.py`. The full View A counterpart ships in `*_view_a`-suffixed columns in the released results database.

### 4.8. Statistical methods

Per-instance pass@1 is averaged across the three seeds, giving one value per instance per arm. For binary outcomes such as resolve and acc@k, this value lies in `{0, 1/3, 2/3, 1}`. For continuous outcomes such as cost, turns, and tokens, it is the per-instance mean across seeds.

Paired tests use the two-sided Wilcoxon signed-rank test with normal approximation on these per-instance pass@1 values between arm pairs. McNemar's test does not apply because the per-instance pass@1 metric is no longer binary at the instance level. Per-arm aggregates are reported as the mean of seed means with across-seed standard deviation as a variance estimate. Per-seed resolve values appear in Table III.

The implementation is pure standard library and lives in `analysis/stats.py`. Zero differences are dropped under the standard Wilcoxon convention, and no continuity correction is applied, matching `scipy.stats.wilcoxon` defaults.

The body reports unadjusted *p*-values across ten paired tests in §6—five metrics times two arm pairs. Readers preferring a family-wise correction at α = 0.05 can apply Holm or Bonferroni correction at *m* = 10.

### 4.9. Pilot disclosure

An earlier batch of runs evaluated two additional configurations that did not enter the main study.

**Aider** was dropped because it rebuilds the full prompt—repository map plus file contents—on every turn, defeating stable-prefix prompt caching. This is structural to Aider's prompt-assembly path rather than a configuration that could be tuned around, and it moves Aider outside the comparable cost band of the tool-using loops in this study.

**Kimi K2.6** was dropped because its heavier retrieved context triggered a deterministic stream-decode failure cluster on heavy instances, taking those cells out of comparability with the rest of the grid.

The pilot cells are released at `data/pilot/pilot_results_public.{db,csv}`.

## 5. Integrity and Threats to Validity

The integrity load for this study sits in four places: pre-run hardening of the per-cell sandbox, a post-run audit that re-checked every retained cell for residual leakage, the exclusion taxonomy explaining which cells were dropped and why, and a named threats list identifying residual concerns the audit could not eliminate.

The released artifacts supporting this section are `data/exclusion_ledger.csv`, `scoring/leak_audit.py`, and `scoring/localization.py`.

### 5.1. Pre-run hardening

Two mechanisms ran before every cell.

**URL redaction.** Self-links in problem statements were stripped at specification-build time, preventing the agent from navigating to a canonical-fix page through the prompt.

**Git scrub.** Every cell starts from a sandbox whose repository has the gold-fix commit and its descendants stripped. Deleting refs alone is insufficient because `git show <hash>` can still recover any object present in the object database. The hardened path therefore runs `git gc --prune=now` to physically remove dropped objects. A post-scrub object-set check then verifies that no future-commit objects remain reachable. If any remain, the cell is marked `scrub=DIRTY` and aborted before the agent runs. Only `scrub=CLEAN` cells execute.

In the released set, 12 cells tripped this fail-closed gate and appear in the ledger as `scrub_failed`. The trip is whole-instance and arm-independent, so the distribution is balanced across the three arms (Table II).

### 5.2. Post-run audit

After the run completed, the authors re-executed `leak_audit.py` over 386 archived traces from the released set as an S1 reviewer pass. The audit found five additional `git_history_leak` cells: the agent had invoked `git show <historical-hash>` on a past commit whose diff touches a gold file.

These commits are in the base history and pre-date the scrub window; removing them would change the task specification. The five cells were excluded outcome-blind—regardless of arm or outcome. The per-arm breakdown and which had `resolved=1` appear in the ledger and Table II.

After exclusion, the residual impact on every reported metric is under one percentage point, and no metric ordering flips. The triple-intersection paired *n* moved from 79 to 75. A network-fetch audit was re-run on the same 386 traces and came back clean: no retained cell fetched a high-severity hosting URL.

The in-ancestry class itself—where the gold fix is reachable in base history—is a dataset limitation that detect-and-exclude can shrink but not eliminate. The sub-one-percentage-point residual is what survives in the released set.

### 5.3. Exclusion taxonomy and public ledger

Twenty-six cells were excluded across five categories. Every excluded cell is removed before resolve, cost, and localization rates are computed; only legitimate cells enter denominators (§4.6).

Three balance points are important. `scrub_failed` is whole-instance balanced across arms, which is the posture the fail-closed gate is designed to produce. `provider_truncation` is arm-asymmetric: all five exclusions fall on the SuperCoder arms. `git_history_leak` and `leak_detected` round out the ledger.

#### Table II — Exclusion taxonomy

| Category | SC-ON | SC-OFF | OpenCode | Total |
|---|---:|---:|---:|---:|
| `scrub_failed` | 4 | 4 | 4 | 12 |
| `provider_truncation` | 2 | 3 | 0 | 5 |
| `git_history_leak` | 1 | 2 | 2 | 5 |
| `leak_detected` | 0 | 0 | 3 | 3 |
| `install_failure` | 0 | 0 | 1 | 1 |
| **Total** | **7** | **9** | **10** | **26** |

Counts are recomputed from `data/exclusion_ledger.csv`; row totals sum to 26 across five categories. All excluded cells are removed from rate denominators.

The public ledger contains one row per excluded cell with columns `cell_id`, `instance_id`, `harness`, `arm`, `exclusion_reason`, and `evidence`. The evidence column quotes the concrete trigger. For `git_history_leak` rows, this includes the literal `git show <hash>` invocation against the gold file.

The ledger went through a three-check audit pass:

1. **Structural:** every excluded `cell_id` resolves in the main database.
2. **Forensic:** each `git_history_leak` row was hand-confirmed against its trace.
3. **Gold-set verification:** every `instance_id`'s gold-file set matches the benchmark specification.

### 5.4. Threats to validity

Six residual threats survive hardening and audit.

**Paired-n limits.** Effective denominators are 75 for the triple intersection, 80 for SC-ON versus SC-OFF, and 78 for SC-ON versus OpenCode. Resolve-level paired tests are underpowered at these sizes, and §6 states that limitation at every test.

**Language coverage.** Three of five SWE-PolyBench languages are represented: Go, Java, and Python. JavaScript and TypeScript were not run, so generalization beyond these three is not warranted.

**Provider-truncation asymmetry.** All five truncation exclusions fall on the SuperCoder arms, with none on OpenCode. Because the cells are excluded rather than scored, the asymmetry does not directly bias the reported rates, but what was lost differs across arms.

**Localization-extractor sensitivity.** The metric admits two defensible computations. Both views are reported (§4.7, §6), and dual-view disclosure is the mitigation.

**In-ancestry leak residual.** Where the gold fix is reachable in base history, the scrub cannot remove it without altering the task. Detect-and-exclude (§5.2) shrinks but cannot eliminate this class.

**Issue-text phrasing realism.** The agent receives formal GitHub-issue text from upstream benchmarks. Garg et al. [5] show that mutating issue text into realistic chat-style queries derived from agent telemetry can drop measured pass rates by over 50% on some models. Detect-and-exclude does not address this ecological-validity gap. Absolute resolve rates should therefore be read as benchmark-conditional. The within-harness ablation is robust to this gap because both arms see identical text.

## 6. Results

Three arms—SC-ON, SC-OFF, and OpenCode—ran Claude Opus 4.7 across three seeds against the same SWE-PolyBench Verified and SWE-bench Pro instances. Each subsection states the point estimate first and then the paired-statistics line.

Paired tests use two-sided Wilcoxon signed-rank tests with normal approximation on per-instance pass@1 averaged across three seeds. For binary outcomes such as resolve and acc@5, per-instance pass@1 lies in `{0, 1/3, 2/3, 1}`. For continuous outcomes, it is the per-instance mean. Acc@5 is reported under View B throughout.

### Table III — Resolve percentage per seed

| Arm | Seed 0 | Seed 1 | Seed 2 | Mean | Std. dev. |
|---|---:|---:|---:|---:|---:|
| SC-ON | 48.8 | 53.6 | 48.8 | **50.4** | 2.75 |
| SC-OFF | 43.9 | 41.5 | 40.2 | 41.9 | 1.86 |
| OpenCode | 44.4 | 45.7 | 45.7 | 45.3 | 0.71 |

The direction is consistent across seeds for SC-ON over both comparators.

### Table IV — Headline metrics across the three arms

Values are means of seed means across three seeds. Acc@5 is View B. Turns, tokens, and wall-clock are per-cell means on legitimate cells.

| Metric | SC-ON | SC-OFF | OpenCode |
|---|---:|---:|---:|
| Resolve % | **50.4** | 41.9 | 45.3 |
| Localization acc@5, View B | **84.5** | 44.3 | 75.3 |
| Recall@5 | **0.611** | 0.330 | 0.601 |
| $/solved | **$2.30** | $2.84 | $2.92 |
| $/cell, mean | **$1.15** | $1.19 | $1.32 |
| Turns, mean | **28.3** | 36.2 | 36.0 |
| Tokens, thousands, mean | **10.1** | 11.1 | 14.0 |
| Wall-clock, minutes, mean | **4.5** | 5.5 | 5.4 |

### 6.1. Cross-harness comparison: SC-ON versus OpenCode

SC-ON resolves 50.4% on average across the three seeds, against OpenCode's 45.3% (paired Wilcoxon on per-instance pass@1, *n* = 78, Δ = +6.0 percentage points, *p* = 0.087). The direction is consistent across all three seeds but does not separate at the conventional threshold. The within-harness ablation in §6.2 gives the cleanest read.

#### Figure 2 — Cost–resolve plane, transformed into text

The original scatter plot places mean per-cell cost on the horizontal axis and resolve percentage on the vertical axis, with error bars showing across-seed standard deviation. It also overlays dashed iso-cost-per-solve curves at approximately $2.30, $2.80, and $3.30 per solved task.

- **SC-ON** is near $1.15 per cell and 50.4% resolve, on the $2.30-per-solved curve.
- **SC-OFF** is near $1.19 per cell and 41.9% resolve, corresponding to $2.84 per solved task.
- **OpenCode** is near $1.32 per cell and 45.3% resolve, corresponding to $2.92 per solved task.

**Main point:** SC-ON occupies the upper-left position—higher resolve at lower or comparable per-cell cost—and has the lowest cost per solved task. The paper's cost claim depends on the joint cost–resolve position, not per-cell cost alone.

#### Cost

SC-ON's mean $/solved is $2.30 against OpenCode's $2.92, about 21% lower. Per-cell mean cost is statistically null (paired Wilcoxon, *p* = 0.35). The $/solved gap is driven by SC-ON's higher resolve rate at comparable per-cell spend. The substantive claim is that the structural codebase index is not more expensive to run than agentic grep; on these benchmarks it is favorable.

#### Effort

SC-ON converges with fewer turns and fewer tokens. Mean turns per cell are 28.3 for SC-ON against 36.0 for OpenCode (paired Wilcoxon, *p* < 0.0001). Mean tokens are 10.1k against 14.0k (also *p* < 0.0001). Mean wall-clock is 4.5 against 5.4 minutes.

The within-harness ablation in §6.2 gives the clearest mechanism: the index shortens the agent's path to the relevant files, and saved tool calls compound into saved tokens and time.

#### Localization

Under View B, SC-ON acc@5 averages 84.5% across seeds against OpenCode's 75.3% (paired Wilcoxon, Δ = +8.1 percentage points, *p* = 0.080). Under legacy View A, the cross-harness comparison shifts because View A counts engine result-list paths as files the agent reached, an asymmetry that inflates surfaced sets only for SC-ON. Full View A and View B tables ship in the released results database.

### 6.2. Causal ablation: index on versus off

The index is the only change between the two arms. Model, remaining tool set, sandbox, prompts, seeds, and caps are held fixed.

#### Table V — Causal ablation, SC-ON versus SC-OFF

| Metric | SC-ON | SC-OFF | Difference | Paired *p* |
|---|---:|---:|---:|---:|
| Resolve % | 50.4 | 41.9 | +7.9 pp | 0.003 |
| Localization acc@5, View B | 84.5 | 44.3 | +39.6 pp | < 0.0001 |
| Recall@5 | 0.611 | 0.330 | +0.281 | < 0.0001 |
| Turns, mean | 28.3 | 36.2 | -8.3 | < 0.0001 |
| Tokens, thousands, mean | 10.1 | 11.1 | -1.6 | 0.027 |
| $/cell, mean | $1.15 | $1.19 | -$0.118 | 0.73, null |
| $/solved | $2.30 | $2.84 | -$0.54 | not applicable |

Paired tests are two-sided Wilcoxon signed-rank tests with normal approximation on per-instance pass@1 averaged across seeds. $/solved is a per-arm aggregate, so no paired test applies.

#### Localization

Under View B, SC-ON acc@5 averages 84.5% across seeds against SC-OFF's 44.3% (paired Wilcoxon on per-instance pass@1, *n* = 80, Δ = +39.6 percentage points, *p* < 0.0001). View B is used for the reasons in §6.1.

#### Figure 3 — First-gold rank CDF, transformed into text

The original line chart plots rank cutoff `k` on a log-scaled horizontal axis at `k ∈ {1, 3, 5, 10}` and the cumulative fraction of legitimate cells whose first gold file appears at rank ≤ `k` on the vertical axis.

At rank 1:

- SC-ON places a gold file first in **77.4%** of cells.
- OpenCode does so in **58.4%**.
- SC-OFF does so in **33.3%**.

At rank 5, the curves equal the paper's View B acc@5 values by construction: **84.5% for SC-ON, 75.3% for OpenCode, and 44.3% for SC-OFF**. The SC-ON lead narrows but does not close at rank 10.

**Main point:** SC-ON dominates at low ranks, the regime that matters most under a limited read budget. The structural index does not merely retrieve a correct file somewhere; it places gold files much earlier in the agent-targeted sequence.

For OpenCode and SC-OFF, View A and View B coincide because neither arm makes context-engine calls.

#### Resolve

SC-ON solves 50.4% of legitimate cells on average across seeds against SC-OFF's 41.9% (paired Wilcoxon, Δ = +7.9 percentage points, *n* = 80, *p* = 0.003). The direction is consistent across seeds.

Taken together, the three signals are: a large localization gain, a statistically separated resolve gain, and no per-cell cost regression.

#### Cost and effort

The index changes how the agent uses tokens, not how much each cell costs. Mean turns fall from 36.2 to 28.3 with the index enabled (paired Wilcoxon, *p* < 0.0001). Mean tokens fall from 11.1k to 10.1k (*p* = 0.027). Per-cell mean cost is statistically null (Δ = -$0.118, *p* = 0.73).

The index therefore buys fewer turns without a per-cell cost penalty. $/solved is lower for SC-ON—$2.30 versus $2.84—because of the higher resolve rate at near-equal per-cell spend.

### 6.3. Where the index helps: exploratory heterogeneity

The slices in this subsection are exploratory. Per-language bucket *n* ranges from 18 to 46. No significance claims are made.

#### By language

Across seeds, localization gains are largest in Go—View B acc@5 of 95.4% ON versus 44.8% OFF—and Python—82.9% versus 42.4%. Java is more modest at 71.7% versus 46.7%.

#### Table VI — Resolve and View B acc@5 by language

| Language (n ON/OFF/OC) | Resolve SC-ON | Resolve SC-OFF | Resolve OpenCode | Acc@5 SC-ON | Acc@5 SC-OFF | Acc@5 OpenCode |
|---|---:|---:|---:|---:|---:|---:|
| Go (29/29/31) | 47.1 | 29.9 | 35.5 | 95.4 | 44.8 | 86.0 |
| Java (20/20/19) | 60.0 | 53.3 | 57.9 | 71.7 | 46.7 | 66.7 |
| Python (35/33/31) | 47.6 | 45.5 | 47.3 | 82.9 | 42.4 | 69.9 |

Resolve directionally favors SC-ON in every language: Go 47.1% versus 29.9%, Java 60.0% versus 53.3%, and Python 47.6% versus 45.5%. On Python, the localization advantage is substantial—82.9% versus 42.4%—while the resolve advantage is narrower but no longer directionally negative.

#### Figure 4 — View B acc@5 by gold-file count, transformed into text

The original grouped bar chart splits tasks by the number of gold files: one file, two files, and three or more files. Each bucket compares SC-ON, SC-OFF, and OpenCode.

| Gold-file bucket | SC-ON | SC-OFF | OpenCode |
|---|---:|---:|---:|
| 1 file | 85.3% | 42.1% | 74.2% |
| 2 files | 74.1% | 49.0% | 70.4% |
| 3+ files | 91.3% | 44.9% | 81.2% |

The buckets contain 46, 18, and 27 distinct instances, respectively. The within-harness gap—SC-ON minus SC-OFF—is largest in the three-or-more-file bucket at **46.4 percentage points**.

**Main point:** the index's largest localization gains appear when a change spans several files, matching the call-graph intuition that structural reachability provides more value as multi-file coordination becomes more important. This analysis is exploratory and does not claim significance.

Per-bucket resolve is directionally positive for SC-ON in every file-count bucket:

- one file: 52.7% versus 41.3%;
- two files: 55.6% versus 51.0%;
- three or more files: 42.0% versus 36.2%.

### 6.4. Sensitivity

Full localization tables under both views ship in the released results database.

**Localization extractor.** Both views are emitted by `scoring/localization.py` from the same trace set. The database's canonical acc@k columns are View B. View A is recomputable locally from traces. The released script states the extraction rule precisely.

**Audit residuals.** The five outcome-blind `git_history_leak` cells flagged in the post-run audit (§5) move every headline metric by at most one percentage point when excluded, and no ranking flips. The network-fetch audit was clean.

**What the paper does not claim.** The SC-ON versus OpenCode comparisons on resolve and View B acc@5 are marginal at multi-seed: paired Wilcoxon *p* = 0.087 and *p* = 0.080, respectively. The within-harness ablation is the cleaner read. Across-seed standard deviations are 0.7–3.3 percentage points on resolve and acc@5, consistent with recently reported coding-agent benchmark noise floors; the reported ablation effects exceed this noise by approximately three to ten times.

## 7. Discussion

### What the ablation says

SC-ON and SC-OFF differ only in the two engine tools (§4.1, §3.2). Model, prompts, sandbox, scorer, seeds, caps, and the remaining tool set are held identical, so the within-harness deltas can be read causally as effects of the index.

View B acc@5 moves from 44.3% to 84.5% (paired Wilcoxon, *p* < 0.0001), and resolve moves from 41.9% to 50.4% (paired *p* = 0.003). Per-cell mean cost is statistically null (*p* = 0.73), while turns and tokens both fall significantly. The substantive interpretation is that the index moves localization a great deal, moves resolve significantly, and is cost-neutral at the cell level while favorable on $/solved.

### Cross-harness validity

SC-ON matches or modestly favors OpenCode on resolve (*p* = 0.087) and View B acc@5 (*p* = 0.080), directionally in SC-ON's favor across seeds but not at conventional significance. The structural codebase index does not duplicate behavior that competent agentic grep already reaches; at minimum, against a competent grep-and-read comparator, it does not regress the agent on the metrics that decide the task.

The cross-harness effort gap is where the arms separate cleanly: SC-ON converges in fewer turns and fewer tokens, both with *p* < 0.0001.

### Where the index does not help—or is not shown to help

The SC-ON versus OpenCode comparisons on resolve and View B acc@5 are marginal at conventional significance thresholds (§6.1). The within-harness ablation is the cleanest read of the index's contribution.

### Implications for harness design

The implications are conditional observations, not prescriptions. The largest causal localization gain in the data appears in the three-or-more-file gold bucket (§6.3, Figure 4), consistent with the call-graph intuition: when a change spans files, a structural index that ranks paths by reachability pays off more than agentic grep over the working copy.

The cost-favorable finding simplifies the deployment question. At a fixed model and comparable caps, a structural codebase index is the lower-$-per-solved arm on these benchmarks, so the per-task gain comes from localization quality and the downstream turn savings it enables.

### Conclusion

This study reports a leak-audited, model-controlled, causal ablation of a shipped structural codebase index inside a coding-agent harness, paired with a cross-harness validity check against an agentic-grep comparator.

The index causally moves localization substantially and resolve with statistical separation—50.4% versus 41.9% resolve, paired Wilcoxon *p* = 0.003—at no per-cell cost penalty and lower $/solved than either the within-harness OFF arm or the OpenCode comparator.

The released artifacts—the exclusion ledger, audit script, and dual-view localization extractor—support the integrity claims in §5 and the result numbers in §6. At this model and on these benchmarks, the deployment question for a structural codebase index is not whether it is too expensive to run, but whether the workload includes multi-file changes where structural ranking pays off.

## References

1. Anthropic. “Introducing Claude Opus 4.7.” Anthropic blog post, 2026. https://www.anthropic.com/news/claude-opus-4-7
2. Sahil Sen, Akhil Kasturi, Elias Lumer, Anmol Gulati, and Vamse Kumar Subbiah. “Is grep all you need? How agent harnesses reshape agentic search.” arXiv preprint arXiv:2605.15184, 2026. https://arxiv.org/abs/2605.15184
3. Reem Aleithan, Haoran Xue, Mohammad Mahdi Mohajer, Elijah Nnorom, Gias Uddin, and Song Wang. “SWE-Bench+: Enhanced coding benchmark for LLMs.” arXiv preprint arXiv:2410.06992, 2024. https://arxiv.org/abs/2410.06992
4. Shanchao Liang, Spandan Garg, and Roshanak Zilouchian Moghaddam. “The SWE-Bench illusion: When state-of-the-art LLMs remember instead of reason.” arXiv preprint arXiv:2506.12286, 2025. https://arxiv.org/abs/2506.12286
5. Spandan Garg, Benjamin Steenhoek, and Yufan Huang. “Saving SWE-Bench: A benchmark mutation approach for realistic agent evaluation.” arXiv preprint arXiv:2510.08996, 2025. https://arxiv.org/abs/2510.08996
6. SuperAGI Research and SuperCoder Contributors. “SuperCoder: An autonomous AI coding-agent harness.” GitHub repository, 2024. https://github.com/TransformerOptimus/SuperCoder
7. SST and OpenCode Contributors. “OpenCode: The AI coding agent built for the terminal.” GitHub repository, 2025. https://github.com/sst/opencode
8. John Yang, Carlos E. Jimenez, Alexander Wettig, Kilian Lieret, Shunyu Yao, Karthik Narasimhan, and Ofir Press. “SWE-agent: Agent-computer interfaces enable automated software engineering.” *Advances in Neural Information Processing Systems (NeurIPS)*, 2024. https://arxiv.org/abs/2405.15793
9. Xingyao Wang, Boxuan Li, Yufan Song, Frank F. Xu, Xiangru Tang, Mingchen Zhuge, Jiayi Pan, Yueqi Song, Bowen Li, et al. “OpenHands: An open platform for AI software developers as generalist agents.” *International Conference on Learning Representations (ICLR)*, 2025. https://arxiv.org/abs/2407.16741
10. Paul Gauthier and Aider Contributors. “Aider: AI pair programming in your terminal.” GitHub repository, 2026. https://github.com/Aider-AI/aider
11. Yuntong Zhang, Haifeng Ruan, Zhiyu Fan, and Abhik Roychoudhury. “AutoCodeRover: Autonomous program improvement.” *Proceedings of the 33rd ACM SIGSOFT International Symposium on Software Testing and Analysis (ISSTA)*, 2024. https://arxiv.org/abs/2404.05427
12. Fengji Zhang, Bei Chen, Yue Zhang, Jacky Keung, Jin Liu, Daoguang Zan, Yi Mao, Jian-Guang Lou, and Weizhu Chen. “RepoCoder: Repository-level code completion through iterative retrieval and generation.” *Proceedings of the 2023 Conference on Empirical Methods in Natural Language Processing (EMNLP)*, 2023. https://arxiv.org/abs/2303.12570
13. Ramakrishna Bairi, Atharv Sonwane, Aditya Kanade, D. C. Vageesh, Arun Iyer, Suresh Parthasarathy, Sriram Rajamani, B. Ashok, and Shashank Shet. “CodePlan: Repository-level coding using LLMs and planning.” arXiv preprint arXiv:2309.12499, 2023; published in FSE 2024. https://arxiv.org/abs/2309.12499
14. Zhaoling Chen, Robert Tang, Gangda Deng, Fang Wu, Jialong Wu, Zhiwei Jiang, Viktor Prasanna, Arman Cohan, and Xingyao Wang. “LocAgent: Graph-guided LLM agents for code localization.” *Proceedings of the 63rd Annual Meeting of the Association for Computational Linguistics (ACL)*, 2025. https://arxiv.org/abs/2503.09089
15. Siru Ouyang, Wenhao Yu, Kaixin Ma, Zilin Xiao, Zhihan Zhang, Mengzhao Jia, Jiawei Han, Hongming Zhang, and Dong Yu. “RepoGraph: Enhancing AI software engineering with repository-level code graph.” arXiv preprint arXiv:2410.14684, 2024. https://arxiv.org/abs/2410.14684
16. Hongyuan Tao, Ying Zhang, Zhenhao Tang, Hongen Peng, Xukun Zhu, Bingchang Liu, Yingguang Yang, Ziyin Zhang, Zhaogui Xu, Haipeng Zhang, Linchao Zhu, Rui Wang, Hang Yu, Jianguo Li, and Peng Di. “Code graph model (CGM): A graph-integrated large language model for repository-level software engineering tasks.” *Advances in Neural Information Processing Systems (NeurIPS)*, 2025. https://arxiv.org/abs/2505.16901
17. Chunqiu Steven Xia, Yinlin Deng, Soren Dunn, and Lingming Zhang. “Agentless: Demystifying LLM-based software engineering agents.” arXiv preprint arXiv:2407.01489, 2024. https://arxiv.org/abs/2407.01489
18. Myeongsoo Kim, Dingmin Wang, Siwei Cui, Farima Farmahinifarahani, Terry Yue Zhuo, Shweta Garg, Baishakhi Ray, Rajdeep Mukherjee, and Varun Kumar. “Coherence collapse: Diagnosing why code agents fail after reaching the right code.” arXiv preprint arXiv:2603.24631, 2026. https://arxiv.org/abs/2603.24631
19. Shaoqiu Zhang, Yuhang Wang, Jialiang Liang, Yuling Shi, Wenhao Zeng, Maoquan Wang, Shilin He, Ningyuan Xu, Siyu Ye, Kai Cai, and Xiaodong Gu. “SWE-Explore: Benchmarking how coding agents explore repositories.” arXiv preprint arXiv:2606.07297, 2026. https://arxiv.org/abs/2606.07297
20. Carlos E. Jimenez, John Yang, Alexander Wettig, Shunyu Yao, Kexin Pei, Ofir Press, and Karthik Narasimhan. “SWE-bench: Can language models resolve real-world GitHub issues?” *International Conference on Learning Representations (ICLR)*, 2024. https://arxiv.org/abs/2310.06770
21. Neil Chowdhury, James Aung, Jun Shern Chan, and Oliver Jaffe. “Introducing SWE-bench Verified.” OpenAI blog post, 2024. https://openai.com/index/introducing-swe-bench-verified/
22. Muhammad Shihab Rashid, Christian Bock, Yuan Zhuang, Alexander Buchholz, Tim Esler, Simon Valentin, Luca Franceschi, Martin Wistuba, Prabhu Teja Sivaprasad, Woo Jung Kim, Anoop Deoras, Giovanni Zappella, and Laurent Callot. “SWE-PolyBench: A multi-language benchmark for repository level evaluation of coding agents.” arXiv preprint arXiv:2504.08703, 2025. https://arxiv.org/abs/2504.08703
23. Xiang Deng, Jeff Da, Edwin Pan, Yannis Yiming He, Charles Ide, Kanak Garg, Niklas Lauffer, Andrew Park, Nitin Pasari, Chetan Rane, Karmini Sampath, Maya Krishnan, Srivatsa Kundurthy, Sean Hendryx, Zifan Wang, Vijay Bharadwaj, Jeff Holm, Raja Aluri, Chen Bo Calvin Zhang, Noah Jacobson, Bing Liu, and Brad Kenstler. “SWE-Bench Pro: Can AI agents solve long-horizon software engineering tasks?” arXiv preprint arXiv:2509.16941, 2025. https://arxiv.org/abs/2509.16941
24. Shunyu Yao, Jeffrey Zhao, Dian Yu, Nan Du, Izhak Shafran, Karthik Narasimhan, and Yuan Cao. “ReAct: Synergizing reasoning and acting in language models.” *International Conference on Learning Representations (ICLR)*, 2023. https://arxiv.org/abs/2210.03629
25. Timo Schick, Jane Dwivedi-Yu, Roberto Dessì, Roberta Raileanu, Maria Lomeli, Luke Zettlemoyer, Nicola Cancedda, and Thomas Scialom. “Toolformer: Language models can teach themselves to use tools.” *Advances in Neural Information Processing Systems (NeurIPS)*, 2023. https://arxiv.org/abs/2302.04761
26. Bjarni Haukur Bjarnason, Andre Silva, and Martin Monperrus. “On randomness in agentic evals.” arXiv preprint arXiv:2602.07150, 2026. https://arxiv.org/abs/2602.07150
