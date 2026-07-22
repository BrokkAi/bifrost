#!/usr/bin/env bash

set -euo pipefail

readonly ZIZMOR_VERSION="1.28.0"

output_format="plain"
if [[ "${GITHUB_ACTIONS:-false}" == "true" ]]; then
  output_format="github"
fi

exec uvx "zizmor@${ZIZMOR_VERSION}" \
  --offline \
  --strict-collection \
  --min-severity medium \
  --format "$output_format" \
  .
