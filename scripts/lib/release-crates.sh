#!/usr/bin/env bash

# Shared inventory of the crates a release packages.
#
# Two callers need exactly this set: scripts/public/check-workspace-packages.sh, which
# proves the archives are well formed, and scripts/public/package-release-crates.sh,
# which builds the archives a readiness run qualifies. Until this file existed
# both carried their own copy of the list and of the eighteen Cargo patch
# arguments, so adding a crate to one and not the other would qualify a release
# that silently omits it.
#
# Order is publication order, not alphabetical: `cargo package` resolves each
# archive against the patched paths, and the facade must come last.

RELEASE_CRATES=(
  brokk-bifrost-core
  brokk-bifrost-cpp
  brokk-bifrost-csharp
  brokk-bifrost-go
  brokk-bifrost-js-ts
  brokk-bifrost-jvm
  brokk-bifrost-php
  brokk-bifrost-python
  brokk-bifrost-ruby
  brokk-bifrost-rust
  brokk-bifrost-rql
  brokk-bifrost-analysis
  brokk-bifrost-nlp
  brokk-bifrost-policy
  brokk-bifrost-semantic-packs
  brokk-bifrost-runtime
  brokk-bifrost-mcp
  brokk-bifrost-lsp
  brokk-bifrost
)

# The facade is the workspace root package; every other crate lives in
# crates/<name without the brokk- prefix>.
RELEASE_CRATE_FACADE=brokk-bifrost

# Stable Cargo requires registry-resolvable versions even with --no-verify.
# These command-local patches make the not-yet-published implementation set
# resolvable while leaving each normalized archive manifest registry-ready.
# Deriving them from RELEASE_CRATES is what keeps the two lists from drifting.
RELEASE_CRATE_PATCH_ARGS=()
for _release_crate in "${RELEASE_CRATES[@]}"; do
  if [[ "$_release_crate" == "$RELEASE_CRATE_FACADE" ]]; then
    continue
  fi
  RELEASE_CRATE_PATCH_ARGS+=(
    --config "patch.crates-io.${_release_crate}.path=\"crates/${_release_crate#brokk-}\""
  )
done
unset _release_crate
