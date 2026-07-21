# Task-ranked C#, Go, Java, JavaScript, and TypeScript reference differential

## Outcome

The live 2026-07-21 selection from `tasks.task_repos(tasks.SFT_PREDICATES, langs=[LANGUAGE])`, sorted by exact `(-task_count, repo_slug)`, is complete. `SFT_PREDICATES` applies the required `large-repos.csv` exclusion and the build, testsome, binding, generated-prompt, non-fragile-test, and skip gates. The 25 literal repositories were passed explicitly to independent strict, ephemeral-cache runs.

The accepted corpus contains 25 clean completed repository records, 215,001 sampled sites, and 14,431 audited files. It classifies 34,464 sites consistent, 885 editor-only, 1,199 unproven, 178,451 inconclusive, and two raw missing. Both raw rows are reviewed non-actionable Go `package main` declaration clauses that spuriously forward-resolve to entry functions. C#, Java, JavaScript, and TypeScript have zero raw missing, leaving zero actionable residuals.

| Language | Audited files | Sampled | Resolved | Consistent | Editor-only | Unproven | Inconclusive | Raw missing | Actionable |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| C# | 3,166 | 50,000 | 23,741 | 10,768 | 39 | 289 | 38,904 | 0 | 0 |
| Go | 2,369 | 50,000 | 20,776 | 8,621 | 0 | 349 | 41,028 | 2 | 0 |
| Java | 4,813 | 50,000 | 18,627 | 7,390 | 625 | 223 | 41,762 | 0 | 0 |
| JavaScript | 1,202 | 20,557 | 5,766 | 1,973 | 131 | 164 | 18,289 | 0 | 0 |
| TypeScript | 2,881 | 44,444 | 14,952 | 5,712 | 90 | 174 | 38,468 | 0 | 0 |
| **Total** | **14,431** | **215,001** | **83,862** | **34,464** | **885** | **1,199** | **178,451** | **2** | **0** |

All records have `status=completed`, clean Bifrost and repository flags, pinned repository heads, one configuration fingerprint per language, zero file errors, and zero candidate-limit exclusions. The configured 1,000-target cap is explicit: 25,539 distinct target groups yielded 19,606 queried groups, 5,933 deterministically skipped groups, and 9,922 sites attached to skipped groups.

## Selection and evidence

- C#: `granit-fx__granit-dotnet` (110), `riok__mapperly` (85), `ClosedXML__ClosedXML` (68), `tui-cs__Terminal.Gui` (56), `JoshClose__CsvHelper` (53). Artifact `/tmp/reference-differential/csharp-task-top5-d675ad92-live.jsonl`, SHA-256 `637ae355a89ba4d311b5bd6b0c7a126e80b434cb0a170e2f4e9769fa21be2da1`, Bifrost `d675ad92`, fingerprint `333c1c7e943f1bab5042730c348ea6dc723b248888c21b8cfdffc6a4cd4bed30`.
- Go: `afadesigns__zshellcheck` (499), `cli__cli` (476), `open-telemetry__opentelemetry-collector` (377), `router-for-me__CLIProxyAPI` (242), `ollama__ollama` (233). Artifact `/tmp/reference-differential/go-task-top5-d675ad92-live.jsonl`, SHA-256 `3f32668872a863f722047ca5adde87bdb86536e798fa7e76444019e626d2a7d9`, Bifrost `d675ad92`, fingerprint `401da61fb7319be515f6f1195e05da16b9030de11018cfe769cc440d5b5fc1ed`.
- Java: `alibaba__fastjson2` (328), `chinabugotech__hutool` (208), `languagetool-org__languagetool` (192), `halo-dev__halo` (163), `apache__dubbo` (126). Artifact `/tmp/reference-differential/java-task-top5-d675ad92-live.jsonl`, SHA-256 `f2fa8522da962a941b413be719122e3f9ee54fd5182566501a751df09f5cf1d9`, Bifrost `d675ad92`, fingerprint `93a389be4ed31b4b385e6c2b50c4007d8f5b8755e8443272b2c9b3eb83787178`.
- JavaScript: `argoproj__argo-cd` (266), `josephfung__curia` (254), `iamkun__dayjs` (109), `pipe-cd__pipecd` (101), `bancolombia__devsecops-engine-tools` (78). Artifact `/tmp/reference-differential/js-task-top5-bdafddad-final.jsonl`, SHA-256 `7fd363076bb3fa43743826f2485cbb93d3f1faaa46106926fc25a05623078f49`, Bifrost `bdafddad`, fingerprint `4e2100493f415809bff86a802609e65dd80c2520904ebfb5a76516b603512b22`.
- TypeScript: `code-yeongyu__oh-my-openagent` (272), `storybookjs__storybook` (180), `Yeachan-Heo__oh-my-claudecode` (162), `woodpecker-ci__woodpecker` (113), `vuejs__core` (87). Artifact `/tmp/reference-differential/ts-task-top5-d675ad92-live.jsonl`, SHA-256 `4466045daa1bc13a46b01fb564411eef8ec674e185c4973c457b823d82ec5200`, Bifrost `d675ad92`, fingerprint `c352324eb40b78ab19727939becf82281d49d48fb656e4ef6e46f386191dc14d`.

The final release runner was built from clean `bdafddad` and has SHA-256 `c75b91dd254339ea399e7d378c49778a2d7647faf0a4e4590c255bc89574cb60`. C# and Java were conservatively replayed at `d675ad92`; Java's replay was required by upstream inverse-resolution changes and completed in 1h04m35s, while C# completed in 17m12s. The intervening upstream changes before `bdafddad` were `.agents`-only, and #1032 changes only JavaScript definition lookup, so the other four language artifacts retain exact semantic provenance.

## Defects and issue state

Every legitimate defect was filed or broadened before implementation and assigned solely to `jbellis`. All in-scope issues are closed completed: C# #966, #969, #971-#974, #980-#984, #1008, #1009; Go #967-#970; Java #976-#979, #985, #986, #989; JavaScript #944, #964, #1032 (with related #665, #942, #943 also closed); and TypeScript #963-#965. Issue #987 remains outside this ledger because it is a Rust campaign issue.

The live selector replacement exposed #1032 in PipeCD: an unparenthesized arrow parameter was not recognized as a lexical receiver binding, allowing a project-wide dotted-name fallback to select an unrelated generated bundle field. Commit `bdafddad` recognizes the exact tree-sitter `arrow_function.parameter` field. The clean exact production replay now returns `no_definition` (`/tmp/reference-differential/js-pipecd-original-placement-exact-bdafddad.jsonl`, SHA-256 `f4a0904e9466f83a3c1f6b2a396f175488810ab56d53cd9f3246bb0c98cb0eb6`), and the full fixing-head JavaScript replay has zero raw missing. #1032 is closed completed and solely assigned to `jbellis`.

## Validation

`cargo fmt --all -- --check` passed. Isolated `cargo clippy --all-targets --all-features -- -D warnings` passed and removed its managed target. The complete serialized `UV_CACHE_DIR=/tmp/bifrost-uv-cache cargo test --features nlp,python -- --test-threads=1` run passed outside the restricted process sandbox: the library reported 1,472 passed, zero failed, and three ignored, and every binary, integration target, and doc test passed. GitHub CI was not awaited, per the campaign boundary.

The compact 25-record manifest is `task-top5-csharp-go-java-js-ts.jsonl` beside this summary.
