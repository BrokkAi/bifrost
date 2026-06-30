#!/usr/bin/env bash
set -euo pipefail

tag="${1:-${RELEASE_TAG_INPUT:-}}"
if [ -z "${tag}" ]; then
  tag="${GITHUB_REF:-}"
fi

tag="${tag#refs/tags/}"
version="${tag#v}"

if [ -z "${version}" ] || [ "${version}" = "${tag}" ]; then
  echo "Release tag must start with v, got '${tag}'." >&2
  exit 1
fi

if ! [[ "${version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-.+][0-9A-Za-z.-]+)?$ ]]; then
  echo "Release tag '${tag}' does not contain a valid semver version." >&2
  exit 1
fi

if [ -n "${GITHUB_OUTPUT:-}" ]; then
  {
    echo "name=${tag}"
    echo "version=${version}"
  } >> "${GITHUB_OUTPUT}"
else
  printf '%s\n' "${tag}"
fi
