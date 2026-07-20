# C# top-five baseline audit at `adfa8e0f`

## Status

This attempted baseline is diagnostic only and is not accepted campaign evidence. The run was
interrupted before its first successful repository record because the shared Bifrost worktree began
changing during execution. The JSONL contains one clean-provenance engine-error envelope for Azure
PowerShell and no completed analyzer report.

The attempt used:

- Bifrost head `adfa8e0f9d915f998f3f91ddbc36ab5ea0ae220f`, initially clean.
- Release runner SHA-256
  `de662c0f4de22a8ff97f8ccf6b3600ec7c29735a3d7fb682997996143df6977e`.
- Output `/mnt/optane/tmp/reference-differential/csharp-top5-adfa8e0f.jsonl`.
- Log `/mnt/optane/tmp/reference-differential/csharp-top5-adfa8e0f.log`.
- Persisted cache mode, strict reporting, one repository at a time, eight inner workers, 1,000
  sampled files, 10,000 sites, 50,000 candidates per file, 4,194,304 source bytes, 1,000 inverse
  target groups, 1,000 usage files per target, 100,000 usage hits per target, and seed zero.

## Selection preflight

The runner dry run selected the canonical repositories in descending `code_loc` order. Each clone
was clean and matched its pinned corpus commit immediately before launch.

| Repository | `code_loc` | Pinned and observed head |
|---|---:|---|
| `Azure__azure-powershell` | 17,025,991 | `409b39eb8c26a360dfc23929c6da96798ce7bcc8` |
| `Azure__azure-sdk-for-net` | 12,405,892 | `a54cb128cf3d57b22b49fb980e5c3f84db19ee90` |
| `mono__mono` | 9,423,628 | `0f53e9e151d92944cacab3e24ac359410c606df6` |
| `dotnet__runtime` | 8,105,816 | `a0311b3485a8df84608d9aab82aa98e097c21948` |
| `dotnet__roslyn` | 4,975,315 | `f219cabdd558dbf616af9f1d39d8ac50feb5da80` |

The dry run also reported 273 C# metadata members with missing or invalid `code_loc`; these are not
corpus members and did not alter the selected top five.

## Azure PowerShell cache corruption

Azure PowerShell failed before analyzer construction completed. Its durable envelope is
`status=engine_error`, pins clean Bifrost and repository heads, and contains this exact error:

```text
failed to build persisted analyzer: opening the persisted analyzer store at
/mnt/T9/repo-clones/Azure__azure-powershell/.brokk/bifrost_cache.db: cache DB
initialization-state query SQLite error: database disk image is malformed
```

The preserved database metadata is:

- Path: `/mnt/T9/repo-clones/Azure__azure-powershell/.brokk/bifrost_cache.db`
- Size: 4,895,506,432 bytes
- SHA-256: `914bbecdafc9dc6c441b03ca6336739e0b4987080b1fe11eb06043edb4bc6f81`
- Modification time: `2026-07-12 22:34:34.745142295 -0500`
- File identification: SQLite 3.x, schema 4, 1,195,192 pages, writer/read version 2

`PRAGMA integrity_check;` failed with SQLite exit code 11 and `database disk image is malformed`.
The first sandboxed attempt could not open the database because the clone root was read-only there;
the escalated check is the authoritative result.

Source inspection shows `AnalyzerStore::open_for_workspace` delegates to `open_persistent`, which
delegates directly to `cache_db::open_unified_connection`. That path can transactionally rebuild an
invalid schema but has no whole-file corruption recovery. Since the database is explicitly
rebuildable cache data, the proposed operator recovery is to quarantine the existing database under
a checksum-bearing sibling name and allow a new canonical `bifrost_cache.db` to be created. No
quarantine or rebuild was performed during this attempt.

## Interrupted Azure SDK work

Azure SDK for .NET completed workspace construction after 326.8 seconds, inventoried 105,645
eligible files, audited 1,000 files, sampled 10,000 sites from 259,966 structured candidates, and
began forward analysis across 878 sampled files. The process was interrupted at 524/878 forward
files after approximately 14 minutes 45 seconds. It appended no repository envelope, so none of
that partial work is accepted evidence.

The interrupted process reported a 3,336,496 KiB peak RSS and no swap. Host-level process
inspection revealed unrelated C++ corpus processes already consuming substantial CPU and memory;
the initial sandboxed `ps` check ran in an isolated PID namespace and therefore did not reveal
those processes. Future overlap checks must use an escalated host-level `ps` before launch.

## Required restart

Do not resume this output as accepted evidence. After the shared implementation is committed:

1. Confirm the Bifrost worktree and all five C# clones are clean at their intended heads.
2. Rebuild the release runner and record its new checksum.
3. Confirm host-level process isolation with escalated `ps`.
4. Quarantine the checksummed Azure PowerShell cache, preserving the original file, then verify a
   fresh persisted analyzer cache can be created.
5. Launch the same five-repository command under a new clean-head-scoped JSONL/log pair.
6. Require five completed reports and exhaustively classify every raw missing row.
