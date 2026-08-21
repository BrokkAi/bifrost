#!/usr/bin/env bash
# Create the GitHub Release for a synced policy-scan alias tag.
#
# The sync publishes refs only. GitHub Marketplace publishes an Action from a
# release, not from a tag, so an alias repository holding nothing but tags has
# nothing to list -- which is the state v0.10.5 shipped in.
#
# This creates the release object. It does not, and cannot, tick the
# Marketplace checkbox: GitHub exposes no API for publishing an Action listing,
# so that step stays manual in the release UI.
#
# Idempotent. A recovery re-run of a release whose GitHub Release already
# exists leaves it alone rather than failing or duplicating it.
#
# Required environment:
#   RELEASE_TAG             vX.Y.Z tag already pushed to the alias repository
#   POLICY_SCAN_SYNC_TOKEN  token with contents read/write on the alias repo
#   IS_NEWEST               1 when this is the newest vMAJOR.x.y release, else 0.
#                           Computed by sync-policy-scan-action.sh rather than
#                           derived a second time here, so the two cannot
#                           disagree about which release consumers follow.
# Optional:
#   POLICY_SCAN_ALIAS_REPO  owner/name (default BrokkAi/bifrost-policy-scan)
set -euo pipefail

RELEASE_TAG="${RELEASE_TAG:?RELEASE_TAG is required (vX.Y.Z)}"
IS_NEWEST="${IS_NEWEST:?IS_NEWEST is required (1 or 0)}"
ALIAS_REPO="${POLICY_SCAN_ALIAS_REPO:-BrokkAi/bifrost-policy-scan}"
GH_TOKEN="${POLICY_SCAN_SYNC_TOKEN:?POLICY_SCAN_SYNC_TOKEN is required}"
export GH_TOKEN

if [[ ! "${RELEASE_TAG}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "RELEASE_TAG '${RELEASE_TAG}' is not a vX.Y.Z release tag" >&2
  exit 1
fi
if [ "${IS_NEWEST}" != 1 ] && [ "${IS_NEWEST}" != 0 ]; then
  echo "IS_NEWEST '${IS_NEWEST}' must be 1 or 0" >&2
  exit 1
fi

if gh release view "${RELEASE_TAG}" --repo "${ALIAS_REPO}" >/dev/null 2>&1; then
  echo "release ${RELEASE_TAG} already exists in ${ALIAS_REPO}; leaving it unchanged"
  exit 0
fi

# An out-of-order sync -- a recovery dispatch or a backport publishing an older
# version after a newer one -- must not claim "Latest release" on the alias
# repository, for the same reason it does not move the floating major tag.
latest_flag="--latest=false"
if [ "${IS_NEWEST}" = 1 ]; then
  latest_flag="--latest"
fi

# The notes go through a file rather than a heredoc inside a command
# substitution: bash 3.2, which is what macOS ships, mis-parses the latter, and
# this script is expected to run outside a Linux runner during recovery.
notes_file="$(mktemp)"
trap 'rm -f "${notes_file}"' EXIT
cat > "${notes_file}" <<EOF
Bifrost policy-scan action ${RELEASE_TAG}.

This repository is generated: its contents are synced from
[\`BrokkAi/bifrost/.github/actions/policy-scan\`](https://github.com/BrokkAi/bifrost/tree/${RELEASE_TAG}/.github/actions/policy-scan)
on every Bifrost release, with the \`version\` input default and the README's
pinned example rewritten to this tag. Report issues and open pull requests
against [BrokkAi/bifrost](https://github.com/BrokkAi/bifrost).

Release notes for Bifrost ${RELEASE_TAG}:
https://github.com/BrokkAi/bifrost/releases/tag/${RELEASE_TAG}
EOF

gh release create "${RELEASE_TAG}" \
  --repo "${ALIAS_REPO}" \
  --title "${RELEASE_TAG}" \
  --notes-file "${notes_file}" \
  --verify-tag \
  "${latest_flag}"

echo "created release ${RELEASE_TAG} in ${ALIAS_REPO} (${latest_flag})"
