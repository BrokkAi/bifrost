#!/usr/bin/env bash

# Lint every shell entry point under scripts/.
#
# Until #2460 moved the release workflows' logic out of `run: |` blocks there was
# not enough shell in tracked files for this to be worth gating, and the blocks
# themselves were invisible to a linter. Both are now false.
#
# Entry points are discovered by shebang rather than by extension, because the
# test doubles in scripts/fixtures/workflow-shell are named for the commands
# they stand in for and carry no suffix.

set -euo pipefail

script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(cd -- "$script_directory/../.." && pwd)"
cd "$repository_root"

if ! command -v shellcheck >/dev/null 2>&1; then
  echo "::error::shellcheck is not installed; get it from https://www.shellcheck.net/ (brew install shellcheck)" >&2
  exit 1
fi

targets=()
while IFS= read -r candidate; do
  case "$candidate" in
    *.sh)
      targets+=("$candidate")
      continue
      ;;
  esac
  read -r shebang < "$candidate" || continue
  case "$shebang" in
    '#!'*sh|'#!'*sh\ *) targets+=("$candidate") ;;
  esac
done < <(git ls-files 'scripts/*')

(( ${#targets[@]} > 0 )) || {
  echo "::error::found no shell entry points to lint" >&2
  exit 1
}

echo "Linting ${#targets[@]} shell entry points"
# -x follows `source` so a sourced library's definitions are in scope, which is
# what makes the shared helpers in scripts/lib lintable at all. Severity stops
# at warning: style and info findings are advice, and a gate that fails on
# advice gets disabled rather than heeded.
shellcheck -x --severity=warning "${targets[@]}"
echo "shellcheck reported no errors or warnings"
