#!/usr/bin/env bash
# Sync the policy-scan composite action into its standalone alias repository
# so workflows can reference the short form
#
#     uses: BrokkAi/bifrost-policy-scan@v0
#
# instead of the subdirectory form
#
#     uses: BrokkAi/bifrost/.github/actions/policy-scan@vX.Y.Z
#
# The canonical source stays at .github/actions/policy-scan/action.yml in
# this repository. This script publishes a verbatim copy with one rewrite:
# the `version` input default becomes the release tag being published, so
# the alias at any tag installs its own matching Bifrost binary by default.
#
# The alias repository receives one commit per release, the exact release
# tag as a lightweight tag, and a force-moved floating major tag (v0, v1,
# ...). An exact release tag is immutable: if the remote tag already exists
# and the synced content differs, the script fails instead of moving it.
# Only the newest vMAJOR.x.y release may move the floating major tag and
# the default branch; an out-of-order sync of an older release publishes
# its exact tag only, so a recovery re-run can never downgrade consumers.
#
# Required environment:
#   RELEASE_TAG             vX.Y.Z release tag being published
#   POLICY_SCAN_SYNC_TOKEN  token with contents read/write on the alias repo
# Optional:
#   POLICY_SCAN_ALIAS_REPO  owner/name (default BrokkAi/bifrost-policy-scan)
#   POLICY_SCAN_ALIAS_URL   full clone URL override; local tests point this
#                           at a file:// bare repository
set -euo pipefail

RELEASE_TAG="${RELEASE_TAG:?RELEASE_TAG is required (vX.Y.Z)}"
ALIAS_REPO="${POLICY_SCAN_ALIAS_REPO:-BrokkAi/bifrost-policy-scan}"
if [ -n "${POLICY_SCAN_ALIAS_URL:-}" ]; then
  ALIAS_URL="${POLICY_SCAN_ALIAS_URL}"
else
  SYNC_TOKEN="${POLICY_SCAN_SYNC_TOKEN:?POLICY_SCAN_SYNC_TOKEN is required}"
  ALIAS_URL="https://x-access-token:${SYNC_TOKEN}@github.com/${ALIAS_REPO}.git"
fi

if [[ ! "${RELEASE_TAG}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "RELEASE_TAG '${RELEASE_TAG}' is not a vX.Y.Z release tag" >&2
  exit 1
fi
MAJOR_TAG="${RELEASE_TAG%%.*}"

for source_file in \
  .github/actions/policy-scan/action.yml \
  packaging/policy-scan-action/README.md \
  LICENSE.md; do
  if [ ! -f "${source_file}" ]; then
    echo "missing ${source_file}; run from the repository root of a release checkout" >&2
    exit 1
  fi
done

stage="$(mktemp -d)"
trap 'rm -rf "${stage}"' EXIT

cp .github/actions/policy-scan/action.yml "${stage}/action.yml"
cp packaging/policy-scan-action/README.md "${stage}/README.md"
cp LICENSE.md "${stage}/LICENSE.md"

# Pin the `version` input default to the release being published. The
# version input is the only input whose default is a release tag, so the
# rewrite requires exactly one matching line before and after.
default_pattern='^    default: v[0-9][0-9.]*$'
matches="$(grep -c "${default_pattern}" "${stage}/action.yml" || true)"
if [ "${matches}" != 1 ]; then
  echo "expected exactly one version default line in action.yml, found ${matches}" >&2
  exit 1
fi
sed -i.bak "s/${default_pattern}/    default: ${RELEASE_TAG}/" "${stage}/action.yml"
rm -f "${stage}/action.yml.bak"
grep -q "^    default: ${RELEASE_TAG}\$" "${stage}/action.yml"

clone="${stage}/alias-repo"
git clone --depth 1 "${ALIAS_URL}" "${clone}"

if ! git -C "${clone}" rev-parse --verify --quiet HEAD >/dev/null; then
  echo "alias repository ${ALIAS_REPO} has no commits; initialize it with an initial commit first" >&2
  exit 1
fi

git -C "${clone}" config user.name "github-actions[bot]"
git -C "${clone}" config user.email "41898282+github-actions[bot]@users.noreply.github.com"
branch="$(git -C "${clone}" symbolic-ref --short HEAD)"

find "${clone}" -mindepth 1 -maxdepth 1 -not -name .git -exec rm -rf {} +
cp "${stage}/action.yml" "${stage}/README.md" "${stage}/LICENSE.md" "${clone}/"

git -C "${clone}" add -A
changed=1
if git -C "${clone}" diff --cached --quiet; then
  changed=0
  echo "alias repository already matches ${RELEASE_TAG}; no new commit"
else
  git -C "${clone}" commit -m "Sync policy-scan action for ${RELEASE_TAG}" \
    -m "Source: https://github.com/BrokkAi/bifrost/tree/${RELEASE_TAG}/.github/actions/policy-scan"
fi

# A release sync may run out of order: a recovery dispatch or a backport
# publishes an older version while a newer one already exists. The exact
# release tag is still published, but only the newest vMAJOR.x.y release
# may claim the default branch and the floating major tag; anything else
# would downgrade consumers that follow the alias repository head or the
# major tag.
newest_tag="$( { git -C "${clone}" ls-remote origin "refs/tags/${MAJOR_TAG}.*" \
    | awk '{print $2}' \
    | sed 's#^refs/tags/##' \
    | grep -E "^${MAJOR_TAG}\.[0-9]+\.[0-9]+$" || true; \
    echo "${RELEASE_TAG}"; } | sort -V | tail -n 1)"
is_newest=0
if [ "${newest_tag}" = "${RELEASE_TAG}" ]; then
  is_newest=1
fi

remote_tag_commit="$(git -C "${clone}" ls-remote origin "refs/tags/${RELEASE_TAG}" | awk '{print $1}')"
if [ -n "${remote_tag_commit}" ]; then
  if [ "${changed}" = 1 ]; then
    # The branch head differs from the staged content, but the branch may
    # legitimately carry a newer release than the one being re-synced. The
    # immutability check is against the exact tag's own content.
    git -C "${clone}" fetch --quiet origin "refs/tags/${RELEASE_TAG}"
    if ! git -C "${clone}" diff --quiet "${remote_tag_commit}" HEAD; then
      echo "remote tag ${RELEASE_TAG} already exists in ${ALIAS_REPO} but the synced content differs; refusing to move an exact release tag" >&2
      exit 1
    fi
    echo "remote tag ${RELEASE_TAG} already carries the synced content"
    if [ "${is_newest}" = 1 ]; then
      # Recover a partial earlier run that pushed the tag but not the branch.
      git -C "${clone}" push origin "${remote_tag_commit}:refs/heads/${branch}"
    fi
  fi
  target_commit="${remote_tag_commit}"
  echo "remote tag ${RELEASE_TAG} already exists; only ensuring ${MAJOR_TAG} points at it"
else
  target_commit="$(git -C "${clone}" rev-parse HEAD)"
  git -C "${clone}" tag "${RELEASE_TAG}" "${target_commit}"
  if [ "${is_newest}" = 1 ]; then
    git -C "${clone}" push origin "HEAD:refs/heads/${branch}" "refs/tags/${RELEASE_TAG}"
  else
    git -C "${clone}" push origin "refs/tags/${RELEASE_TAG}"
  fi
fi

if [ "${is_newest}" != 1 ]; then
  echo "newest ${MAJOR_TAG}.x.y release in ${ALIAS_REPO} is ${newest_tag}; published ${RELEASE_TAG} as an exact tag only and left ${MAJOR_TAG} and ${branch} untouched"
  exit 0
fi

git -C "${clone}" push --force origin "${target_commit}:refs/tags/${MAJOR_TAG}"

echo "synced ${ALIAS_REPO}@${RELEASE_TAG} (${target_commit}); ${MAJOR_TAG} now points at it"
