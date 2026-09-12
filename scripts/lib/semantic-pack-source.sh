#!/usr/bin/env bash

verify_pinned_archive() {
  local archive_path=$1
  local expected_sha256=$2

  [[ -f "${archive_path}" ]] || return 1
  local actual_sha256
  actual_sha256=$(shasum -a 256 "${archive_path}" | awk '{print $1}')
  [[ "${actual_sha256}" = "${expected_sha256}" ]]
}

fetch_pinned_archive() {
  if [[ $# -ne 4 ]]; then
    echo "usage: fetch_pinned_archive OUTPUT URL SHA256 FILE_NAME" >&2
    exit 2
  fi

  local output=$1
  local url=$2
  local expected_sha256=$3
  local file_name=$4
  local cache_root=${SEMANTIC_PACK_SOURCE_CACHE:-}
  local cache_path=
  local cache_temp=

  if [[ -n "${cache_root}" ]]; then
    mkdir -p "${cache_root}"
    cache_path="${cache_root}/${file_name}"
    cache_temp="${cache_path}.tmp"
  fi

  if [[ -n "${cache_path}" ]] && verify_pinned_archive "${cache_path}" "${expected_sha256}"; then
    cp -f "${cache_path}" "${output}"
  elif verify_pinned_archive "${output}" "${expected_sha256}"; then
    if [[ -n "${cache_path}" ]]; then
      cp -f "${output}" "${cache_temp}"
      verify_pinned_archive "${cache_temp}" "${expected_sha256}"
      mv -f "${cache_temp}" "${cache_path}"
    fi
  else
    rm -f "${output}"
    curl --fail --location --silent --show-error --retry 5 --retry-all-errors \
      --retry-delay 5 --connect-timeout 30 \
      --output "${output}" "${url}"
    verify_pinned_archive "${output}" "${expected_sha256}"
    if [[ -n "${cache_path}" ]]; then
      cp -f "${output}" "${cache_temp}"
      verify_pinned_archive "${cache_temp}" "${expected_sha256}"
      mv -f "${cache_temp}" "${cache_path}"
    fi
  fi

  verify_pinned_archive "${output}" "${expected_sha256}"
}
