#!/usr/bin/env bash

set -euo pipefail

script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(cd -- "$script_directory/.." && pwd)"
security_project="$script_directory/github-actions-security"

output_format="plain"
if [[ "${GITHUB_ACTIONS:-false}" == "true" ]]; then
  output_format="github"
fi

exec uv run \
  --project "$security_project" \
  --locked \
  --isolated \
  zizmor \
  --offline \
  --strict-collection \
  --min-severity medium \
  --format "$output_format" \
  "$repository_root"
