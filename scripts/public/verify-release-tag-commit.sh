#!/usr/bin/env bash
set -euo pipefail

release_tag=${1:?expected an unqualified release tag}
expected_commit=${2:?expected the validated release commit}
tag_ref="refs/tags/${release_tag}"

remote_refs="$(git ls-remote --tags origin "${tag_ref}*")"
actual_commit="$(awk -v tag_ref="$tag_ref" '
  $2 == (tag_ref "^{}") { print $1; found = 1; exit }
  $2 == tag_ref { fallback = $1 }
  END { if (!found && fallback) print fallback }
' <<< "$remote_refs")"

test -n "$actual_commit"
test "$actual_commit" = "$expected_commit"
