# Task-ranked C#, Go, Java, JavaScript, and TypeScript reference differential

> Historical checkpoint: this matrix was authoritative when selected, but a 2026-07-21 live selector audit added three higher-ranked JavaScript repositories and one higher-ranked TypeScript repository. It is not final completion evidence until those replacements are audited and this report is regenerated.

## Outcome

This checkpoint records the completed five-language matrix selected through `tasks.task_repos(tasks.SFT_PREDICATES, langs=[LANGUAGE])`, followed by exact descending filtered task count; `SFT_PREDICATES` applies the required `large-repos.csv` exclusion. The literal five repositories from that selection snapshot were preserved and passed explicitly to independent runner invocations.

The accepted corpus contains 25 clean completed repository records, 231,773 sampled sites, and 14,807 audited files. It classifies 34,700 sites consistent, 948 editor-only, 1,316 unproven, 194,779 inconclusive, and 30 raw missing. Exhaustive source/AST/identity review leaves zero actionable residuals: Go's two rows are `package main` declaration clauses that forward-resolved to entry functions, and JavaScript's 28 rows are invalid cross-binding/global-receiver or definition/write identities rather than inverse omissions. C#, Java, and TypeScript have zero raw missing.

| Language | Audited files | Sampled | Resolved | Consistent | Editor-only | Unproven | Inconclusive | Raw missing | Actionable |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| C# | 3,166 | 50,000 | 23,741 | 10,768 | 39 | 289 | 38,904 | 0 | 0 |
| Go | 2,369 | 50,000 | 20,776 | 8,621 | 0 | 349 | 41,028 | 2 | 0 |
| Java | 4,813 | 50,000 | 18,627 | 7,390 | 625 | 223 | 41,762 | 0 | 0 |
| JavaScript | 1,286 | 31,773 | 8,518 | 1,622 | 103 | 264 | 29,756 | 28 | 0 |
| TypeScript | 3,173 | 50,000 | 16,734 | 6,299 | 181 | 191 | 43,329 | 0 | 0 |
| **Total** | **14,807** | **231,773** | **88,396** | **34,700** | **948** | **1,316** | **194,779** | **30** | **0** |

All records have `status=completed`, clean Bifrost and repository flags, pinned repository heads, one configuration fingerprint per language, zero file errors, and zero candidate-limit exclusions. The configured 1,000-target sample is explicit: 25,522 distinct target groups yielded 19,692 queried groups, 5,830 deterministically skipped groups, and 9,710 sites attached to skipped groups. This is sampling, not an engine error or unreported truncation.

## Selection and per-language evidence

- C# ranks: `granit-fx__granit-dotnet` (110), `riok__mapperly` (85), `ClosedXML__ClosedXML` (68), `tui-cs__Terminal.Gui` (56), `JoshClose__CsvHelper` (53). The final clean artifact pins Bifrost `a328a6737872ee7111d90123325bc9234469f6e5`, fingerprint `333c1c7e943f1bab5042730c348ea6dc723b248888c21b8cfdffc6a4cd4bed30`, and zero raw missing. Raw JSONL: `/mnt/optane/tmp/reference-differential/csharp-task-top5-a328a673-final.jsonl` (SHA-256 `7b54c6e9f1af92deff6caf1120778bff4e1e4ec9fbd4d602e54cedc6712c52b8`); log SHA-256 `341e82ac940de9de0e945cae441933eb25d09456741d1b255576cbceb3a980de`.
- Go ranks: `afadesigns__zshellcheck` (499), `cli__cli` (476), `open-telemetry__opentelemetry-collector` (377), `router-for-me__CLIProxyAPI` (242), `ollama__ollama` (233). The accepted artifact pins Bifrost `94d99c3ac897ae08afaab9d9db67ee32ed9347f8`, fingerprint `401da61fb7319be515f6f1195e05da16b9030de11018cfe769cc440d5b5fc1ed`, and two reviewed non-actionable package-clause rows. Raw JSONL: `/mnt/optane/tmp/reference-differential/go-task-top5-94d99c3a-final.jsonl` (SHA-256 `ce23552cfa0343d5df659de151559216bcf93045d52e2a932b8c1a84ec86b3a9`).
- Java ranks: `alibaba__fastjson2` (328), `chinabugotech__hutool` (208), `languagetool-org__languagetool` (192), `halo-dev__halo` (163), `apache__dubbo` (126). The final clean artifact pins Bifrost `a328a6737872ee7111d90123325bc9234469f6e5`, fingerprint `93a389be4ed31b4b385e6c2b50c4007d8f5b8755e8443272b2c9b3eb83787178`, and zero raw missing. Raw JSONL: `/mnt/optane/tmp/reference-differential/java-task-top5-a328a673-final.jsonl` (SHA-256 `ca7a5c58a0984ee5aa9ee0bbdeb295aafd5f6e389ffed34e703f5a4852c111b8`); log SHA-256 `d8608dd92fda8967741aa6cf691f803e95cf5c117dd160ad545bcdb0255a5915`.
- JavaScript ranks: `josephfung__curia` (254), `iamkun__dayjs` (109), `Hack23__European-Parliament-MCP-Server` (74), `Stormheg__wagtail` (47), `angular__angular.js` (41). The accepted artifact pins Bifrost `94d99c3ac897ae08afaab9d9db67ee32ed9347f8`, fingerprint `4e2100493f415809bff86a802609e65dd80c2520904ebfb5a76516b603512b22`, and 28 reviewed non-actionable rows. Raw JSONL: `/mnt/optane/tmp/reference-differential/js-task-top5-94d99c3a-final.jsonl` (SHA-256 `fc93d05a60907775ef23fd69e184e3f4e289a10b940dd907662f84a4623d297c`).
- TypeScript ranks: `code-yeongyu__oh-my-openagent` (272), `storybookjs__storybook` (180), `Yeachan-Heo__oh-my-claudecode` (162), `vuejs__core` (87), `lerna__lerna` (76). The accepted artifact pins Bifrost `94d99c3ac897ae08afaab9d9db67ee32ed9347f8`, fingerprint `c352324eb40b78ab19727939becf82281d49d48fb656e4ef6e46f386191dc14d`, and zero raw missing. Raw JSONL: `/mnt/optane/tmp/reference-differential/ts-task-top5-94d99c3a-final.jsonl` (SHA-256 `8c24911e5dc923656954583899b3eaaa74afb5749244c97908f072072a31035d`).

Go, JavaScript, and TypeScript did not need another replay after `94d99c3a`: every later analyzer change through `a328a673` is confined to C#, Java, Rust, C, or C++, and the only shared-file deltas are language-specific imports plus a Rust-only analysis epoch. Their accepted records therefore retain exact behavior provenance rather than being rerun without a relevant semantic change.

The release runner used for the final C# and Java replays was built from clean published `a328a673` and has SHA-256 `69b8aa59f9a6f6e4afea5eca87e6507388f8a644c0ebea62721643639a8b9880`. Both final replays used strict mode and ephemeral caches; C# exited 0 after 18m22s and Java exited 0 after 1h11m48s.

## Defects and issue state

Every legitimate defect was filed or broadened before implementation and assigned solely to `jbellis`. The final structured connector audit found every in-scope issue closed as completed:

- C#: #966, #969, #971-#974, #980-#984, #1008, and #1009.
- Go: #967-#970.
- Java: #976-#979, #985, #986, and #989.
- JavaScript: #944 and #964; related earlier #665, #942, and #943 are also closed and solely assigned.
- TypeScript: #963-#965.

The last fixing-head replay found four residual root causes after the first all-language pass. #1008 now recognizes invocation through delegate-valued C# properties; #1009 preserves independent outer and nested generic arities; the reopened #976 now records Java selector receiver type segments; and the reopened #978 prevents exited or sibling local bindings from shadowing active Java fields. Their fixing commits are `43002cdd`, `bdc7678a`, `0ef5a839`, and `abb34275`, respectively, each with clean exact production evidence before the complete final replay.

Issue #987 is not part of this ledger: it is an independently reopened Rust re-export/performance issue from the concurrent Rust campaign and was deliberately left untouched.

## Validation

`cargo fmt --all -- --check` passed. Isolated `cargo clippy --all-targets --all-features -- -D warnings` passed and removed its managed target. The complete serialized `UV_CACHE_DIR=/tmp/bifrost-uv-cache cargo test --features nlp,python -- --test-threads=1` run passed outside the restricted process sandbox: the library reported 1,469 passed, zero failed, and four ignored, and every binary, integration target, and doc test passed. A first sandboxed attempt failed only the three process-I/O `benchmark::mcp_session` tests with `EPERM`; the identical escalated command passed them. GitHub CI was not awaited, per the campaign boundary.

The compact 25-record manifest is `task-top5-csharp-go-java-js-ts.jsonl` beside this summary. It pins each repository head, task rank/count, Bifrost head, fingerprint, counters, issue ledger, raw artifact checksum, and final disposition.

The live 2026-07-21 selector now replaces JavaScript ranks 1, 4, and 5 with `argoproj__argo-cd` (266), `pipe-cd__pipecd` (101), and `bancolombia__devsecops-engine-tools` (78), while retaining Curia and Day.js. It replaces TypeScript rank 4 with `woodpecker-ci__woodpecker` (113), while retaining oh-my-openagent, Storybook, oh-my-claudecode, and Vue. These four repositories are the remaining acceptance work; the displaced Hack23, Wagtail, AngularJS, and Lerna records remain valid supplemental evidence.
