# Task-ranked C++ repositories eleven through twenty

The C++ ranks-eleven-through-twenty leg is complete. The live `tasks.py`
selector supplied the `[10:20]` slice after it applied `large-repos.csv`.
The final runner audited each selected clone at its pinned clean head.

The accepted certification uses clean published Bifrost head
`1ed3c61407ec987688de4f36a666b4ad32c39347`. Its release runner SHA-256 is
`7d943552277b4c9bf9a2eb7964d2bb40692c13a9e7926d6b76aa9195e09c8080`.
Cargo and Bifrost used normal repository storage outside the sandbox. All
campaign processes ran at niceness 10.

| Rank | Repository | Tasks | Files | Sampled | Targets | Consistent | Editor-only | Unproven | Inconclusive | Missing | Runtime |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 11 | `libarchive__libarchive` | 20 | 98 | 8,212 | 330 / 330 | 1,632 | 0 | 91 | 6,489 | 0 | 4.2s |
| 12 | `DaveGamble__cJSON` | 19 | 2 | 571 | 3 / 3 | 142 | 0 | 0 | 429 | 0 | 0.4s |
| 13 | `open62541__open62541` | 19 | 78 | 10,000 | 308 / 308 | 2,985 | 0 | 48 | 6,967 | 0 | 3.9s |
| 14 | `google__wuffs` | 18 | 36 | 10,000 | 613 / 613 | 2,219 | 17 | 70 | 7,694 | 0 | 98.9s |
| 15 | `BehaviorTree__BehaviorTree.CPP` | 18 | 168 | 10,000 | 957 / 957 | 1,920 | 194 | 110 | 7,776 | 0 | 121.6s |
| 16 | `GoogleCloudPlatform__esp-v2` | 17 | 81 | 10,000 | 540 / 540 | 1,661 | 71 | 34 | 8,234 | 0 | 4.2s |
| 17 | `abseil__abseil-cpp` | 16 | 614 | 10,000 | 1,143 / 1,143 | 1,537 | 83 | 121 | 8,259 | 0 | 110.5s |
| 18 | `Mbed-TLS__mbedtls` | 16 | 57 | 4,521 | 91 / 91 | 407 | 0 | 148 | 3,966 | 0 | 1.7s |
| 19 | `pyro-ppl__pyro` | 13 | 1 | 581 | 4 / 4 | 6 | 0 | 0 | 575 | 0 | 1.4s |
| 20 | `cppcheck-opensource__cppcheck` | 13 | 290 | 10,000 | 1,225 / 1,225 | 3,136 | 110 | 34 | 6,720 | 0 | 404.0s |

The final envelope contains 73,885 sampled sites across 1,425 files and
667,798 structured candidates. It queried all 5,214 inverse target groups.
It reports 15,645 consistent, 475 editor-only, 656 honestly unproven, and
57,109 inconclusive rows. It reports zero missing rows.

No repository has a file error, candidate-limit exclusion, skipped target, or
truncated target. All ten Bifrost and corpus worktrees are recorded clean.
The exhaustive missing ledger is empty. Its SHA-256 is
`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

## Findings and fixes

The campaign grouped failures only when they had one structured root cause.
It kept each repository depth-first. This reduced repeated builds while it
kept unrelated resolver defects in separate issues.

Fresh-epoch work created and closed #1697, #1699, #1702 through #1705,
#1684 through #1687, #1716, #1728, and #1734. Earlier work in this same C++
slice also closed the issues listed in the machine manifest. Each issue is
assigned only to `jbellis`. An independent Oldskool review found no open
matching C++ campaign issue.

The final Cppcheck issue, #1734, corrected a visible same-FQN declaration
route. The public symbols API now resolves the witness to the real
`XMLDocument` class body. The final-head exact differential has an exact
inverse hit and zero missing rows. Its SHA-256 is
`86c90046a4eb48508f074d937bc5ab4a84ccba55960d5ca87b96f74d0d3060e3`.

Formatting, focused C++ tests, all C++ usage and alias tests, and featureless
workspace Clippy passed for the final correction. The broad featureless test
gate had one unrelated C# wall-clock failure under full load. The exact C#
test passed alone. The #1734 test also passed after a later analyzer crate
split and after the final unrelated dependency fast-forward.

The complete envelope ran at the published head before that final unrelated
fast-forward. Commit `8c107ce1` changed repository cloning, dependency checks,
and license generation. It did not change C++ code, shared symbol resolution,
or the differential runner. The focused C++ regression passed after that
fast-forward.

## Durable evidence

The machine-readable manifest is
`.agents/docs/reference-differential/cpp-task-ranks11-20-1ed3c614.jsonl`.
The accepted raw JSONL is
`/mnt/optane/tmp/bifrost-fird/cpp-task-ranks11-20-final-1ed3c614.jsonl`.
Its SHA-256 is
`4dd1200ac582e9954dd2b2d786d3225055c12f54f9f708f311a78d4db31c270e`.

The raw final envelope remains in campaign scratch storage for the final
110-envelope reconciliation. Superseded C++ raw reports can now be removed.
