---
name: bifrost-policy-checking
description: >-
  Discover Bifrost policy packs and categories, run built-in and repository
  RQL policies, and interpret clean, finding, and unreliable results. Use for
  policy checks, code-smell checks, category-specific scans, or final
  validation of code changes.
---

# Bifrost Policy Checking

Use Bifrost's `list_policies` and `run_policy` MCP tools to check the active
workspace. Prefer one combined MCP run so built-in and repository policies use
the same immutable analyzer snapshot and produce one canonical report.

## Tools

| Tool | Purpose |
|---|---|
| `list_policies` | Discover built-in packs, categories, policy IDs, and metadata |
| `run_policy` | Evaluate built-in or repository policies against one analyzer snapshot |

## Confirm the tool surface

Both tools belong to Bifrost's `extended` toolset. Before claiming that a
policy check ran, confirm that `list_policies` and `run_policy` are callable.
If this skill is installed but either tool is absent, report a plugin/MCP
registration failure explicitly. Do not replace an unavailable MCP check with
an LSP action or CLI command unless the user asks for that fallback.

For a managed Codex plugin install, run the packaged launcher `doctor` command
when the binary may be missing or incompatible, then start a fresh task after
repairing or updating the plugin. A skill being visible does not prove that its
MCP server contributed tools to the current task.

## Discover packs, categories, and policy IDs

Call `list_policies` with an empty object:

```json
{}
```

Treat its manifest as the source of truth. Report the available pack ID and the
distinct values of `policies[].category`; do not guess category names from the
skill. When useful, include the stable policy IDs within each category.

`bifrost.code-smells` is a pack, not a category. Selecting that pack runs every
built-in code-smell category in the installed release. To run only one or more
categories, pass the exact discovered names through `policy_categories`.

## Select policies

Choose the smallest selector that matches the requested check:

| Intent | `run_policy` selector |
|---|---|
| All policies in one built-in pack | `"policy_packs": ["bifrost.code-smells"]` |
| One or more discovered categories | `"policy_categories": ["performance"]` |
| Exact built-in rules | `"policy_ids": ["bifrost.correctness.dynamic-evaluation"]` |
| Repository-defined executable roots | `"policy_files": [".bifrost/policies/project.rqlp"]` |

Selector arrays form a union, so combine them in one request when the task
requires built-ins and repository policies together. Duplicate selectors and
unknown pack, category, or policy IDs are invalid.

Repository policy files are explicit workspace-relative `.rqlp` roots. First
follow the repository's `AGENTS.md` or policy documentation for the canonical
root list. If discovery is needed, use the host's file-search support, such as
`rg --files -g '*.rqlp'`, then distinguish executable policies from reusable
endpoint or query dependencies before invoking `run_policy`. Do not assume
every file under `.bifrost/policies/` is an executable root, and do not pass
globs.

## Run the check

Supply the current UTC date explicitly because suppression expiration is
deterministic and the MCP service does not read the clock. `warning` is the
normal completion threshold for the built-in code-smell pack:

```json
{
  "policy_packs": ["bifrost.code-smells"],
  "policy_files": [".bifrost/policies/project.rqlp"],
  "evaluation_date": "YYYY-MM-DD",
  "fail_on": "warning"
}
```

Omit `policy_files` when the repository has no project policy roots. By
default Bifrost merges three suppression sources -- `.bifrost/suppressions.json`,
`.bifrost/suppressions.private.json`, and the uncommitted
`.bifrost/suppressions.local.json` -- each optional. Use `suppression_file`
only when the repository names a different reviewed file; it replaces all
three rather than adding to them.
Never create or broaden a suppression merely to make validation green.

## Interpret and report

Read the structured result rather than only the human preview:

- `status: "clean"` / `exit_status: 0`: the selected threshold passed. Confirm
  that the report has no unreliable diagnostics before calling the check green.
- `status: "finding"` / `exit_status: 1`: report policy IDs and exact primary
  locations, fix in-scope findings, and rerun the same selection.
- `status: "unreliable"` / `exit_status: 2`: the check did not establish a
  trustworthy result. Report run completion and diagnostics; never translate
  it into a clean result.

Applied suppressions remain auditable in the canonical report. Mention active,
orphaned, expired, or invalid suppression state when it affects the outcome.

## Accept a finding

A suppression record is a durable review decision this repository keeps so the
same finding is not re-litigated. Write one only after deciding the finding is
genuinely acceptable, and always record `path`:

```json
{
  "policy_id": "<the finding's policy_id>",
  "finding_id": "<the finding's id>",
  "path": "<the finding's primary.path>",
  "identity_stability": "strong",
  "status": "accepted",
  "reason": "<why this specific code is acceptable>",
  "policy_hash_at_acceptance": "<the rule's policy_hash>",
  "accepted_by": "<who decided>",
  "accepted_at": "YYYY-MM-DD"
}
```

Every value comes from the report you just read; none of it is invented. The
`reason` must say why *this* code is acceptable, not that the check was noisy.

Choose the file by the finding's path, not by the repository you are in:

- `.bifrost/suppressions.json` when the finding's file is published.
- `.bifrost/suppressions.private.json` when it is not. Recording an
  unpublished path in the published file would disclose it, and in this
  repository the projection refuses to publish such a record at all.
- `.bifrost/suppressions.local.json` for a decision you are still working out
  and do not intend to commit.

Never write the same finding into two files. Bifrost rejects the run rather
than choosing between them.

`path` is not part of the join key and does not widen the record: a suppression
still applies to exactly one strong identity. It exists because a finding
identity is a hash of the code around the finding, so an ordinary edit near an
accepted finding changes the identity and the record silently stops matching.
With `path` recorded, a run can tell that dead record from one whose file it
simply did not analyze. Without it, it cannot, and the decision rots unnoticed.

## Repair an orphaned record

`orphan_state: "orphaned"` means the run analyzed the record's file and no
finding carries its identity: the decision is dead and the run fails. Repair
it, and do not work around it:

- The review lists `rekey_candidates` -- the policy's unclaimed identities in
  that same file. If one is the same finding under a rotated identity, replace
  the record's `finding_id` with it and keep the original reason, author, and
  date. The decision did not change; only its key did.
- If the finding is genuinely gone -- the code was fixed or deleted -- delete
  the record.

Never silence an orphan by broadening scope, deleting an unrelated record, or
lowering the threshold. If a record cannot be attributed with confidence,
deleting it is correct: the finding will resurface on the next run and can be
accepted again with a path.

For final validation of a code-changing task, record the selected pack,
categories, policy roots, status, and any unresolved findings or diagnostics.
If a Bifrost call takes longer than five seconds, follow the repository's
latency-issue protocol with the exact request and timing.
