# Java task-ranked reference differential at `0b4f1d6f`

## Selection and provenance

This is the authoritative Java leg of the task-ranked campaign. Repository membership came from `tasks.task_repos(tasks.SFT_PREDICATES, langs=["java"])`, followed by a stable descending `task_count` sort. `SFT_PREDICATES` applies the required `large-repos.csv` exclusion. The five repositories were passed to the runner explicitly:

| Repository | Eligible tasks | Pinned head | Queried targets | Missing |
| --- | ---: | --- | ---: | ---: |
| `alibaba__fastjson2` | 328 | `067995902fb586606cccea29aa0579a18b9bbf3a` | 1,000 | 0 |
| `chinabugotech__hutool` | 208 | `a0bd223dc0d036f55cfe4d8e2f5737ddc31f2b12` | 1,000 | 0 |
| `languagetool-org__languagetool` | 192 | `e4bb527d334e0686f04d14a9743cb20249ae328a` | 1,000 | 0 |
| `halo-dev__halo` | 163 | `3f7681fddecb46122503f306f24703c06be3cd6a` | 931 | 0 |
| `apache__dubbo` | 126 | `316df8e57677cc8c1ed6d92bd40ca0daba27393f` | 1,000 | 0 |

The accepted source head is `0b4f1d6f8b3b10009038c7335eb75006ff8bb209`, already pushed to `origin/master` before the run. Its immutable release runner SHA-256 is `e6c0c49fb4447a3e5b74e68988d2fb26b4a3a5ad09321a324a7a7ea7a3e698df`. All Bifrost and repository dirty flags are false, all five records have status `completed`, and every record shares semantic fingerprint `93a389be4ed31b4b385e6c2b50c4007d8f5b8755e8443272b2c9b3eb83787178`.

The campaign used the standard strict bounds: one repository job, eight inner workers, persisted cache mode, 1,000 files, 10,000 sampled sites, 50,000 candidates per file, 4 MiB per source, 1,000 queried targets, 1,000 usage files, 100,000 usages, and seed zero. Targets beyond the configured 1,000-target sample and sites beyond each selected target's usage budget were accounted for by the runner rather than treated as errors. No repository reported a candidate-limit event or file error.

## Result

The final artifact is `/mnt/optane/tmp/bifrost-fird/java-task-top5-0b4f1d6f-clean.jsonl`, SHA-256 `d95fa95d7bdd6678aace61ac2f1b8d273a870d2ab9800382b48eca7bbef4c740`. Its log is `/mnt/optane/tmp/bifrost-fird/java-task-top5-0b4f1d6f-clean.log`, SHA-256 `63bed1ea6fc3399fc9678336fb062e6e3afc0263f693477a49096197f573d355`.

Across 50,000 sampled sites, the runner classified 7,465 consistent, 625 editor-only, 41,748 inconclusive, 162 unproven, and zero missing. It queried 4,931 targets from 6,287 distinct forward targets. Aggregate repository runtime was 3,523.07 seconds; LanguageTool accounted for 3,220.75 seconds and completed all 1,000 inverse targets after the interrupted pre-crash attempt was discarded.

Because the accepted corpus contains no missing row, there is no residual ledger and no new Java issue to assign or repair. Earlier Java fixes remained effective under the current task-ranked selection. The first recovered post-crash replay was retained only as diagnostic evidence because clone dirty flags were captured before operational cache paths were locally excluded; this second replay is the clean acceptance boundary.
