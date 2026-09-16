# Node child_process packs

The declaration packs name the exact reviewed `execSync(command)` member
for JavaScript and TypeScript CommonJS namespace calls. The summaries
packs carry one complete reviewed procedure summary for that member so
value flow can cross the call boundary with honest transfers.

## Reviewed summary claims

The `node.child-process.exec-sync` summary targets the one-argument
`child_process.execSync(command)` member with a receiver. Its reviewed
claims, grounded in the `doc/api/child_process.md` document at Node
`v22.11.0` (SHA-256
`479aee745aaf69e076724d4acda57da20fc3e0dfdba3fe4eb88e38d39c654bcc`,
byte-identical inside the official `node-v22.11.0.tar.gz` archive and at
`https://github.com/nodejs/node/blob/v22.11.0/doc/api/child_process.md`),
are:

- The namespace receiver flows to itself; calling the member does not
  replace the module object.
- The command argument flows to the normal return, whose documented
  value is the spawned command's standard output. Output may echo its
  input, so the transfer is the sound may-analysis claim.
- The command argument flows to the exceptional return. The documented
  throw carries the full spawn result, and its message names the
  command, so thrown values may carry command-derived data.
- The command argument escapes to the `node.child-process.exec-sync.command`
  event: the documented method hands the string to a shell.
- The claim covers every outside-workspace implementation of this
  member, matching the builtin-only namespace the declarations pack
  publishes.

Only the one-argument string form is modeled. Calls with an options
argument do not bind and stay fail-closed. The packs set
`safety.review_required`; activation needs an explicit enable control.
