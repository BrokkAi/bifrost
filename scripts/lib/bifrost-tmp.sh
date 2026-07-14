#!/usr/bin/env bash

bifrost_tmp_root() {
  if [ -n "${BIFROST_TMP_ROOT:-}" ]; then
    printf '%s\n' "${BIFROST_TMP_ROOT}"
  elif [ "$(uname -s)" = "Darwin" ]; then
    printf '%s\n' /private/tmp
  else
    printf '%s\n' "${TMPDIR:-/tmp}"
  fi
}

bifrost_require_tmp_root() {
  if [ ! -d "$1" ]; then
    echo "Temporary root does not exist: $1" >&2
    return 1
  fi
}

bifrost_stat_number() {
  local path="$1"
  local gnu_format="$2"
  local bsd_format="$3"
  local value

  if value="$(stat -c "${gnu_format}" "${path}" 2>/dev/null)" \
    && [[ "${value}" =~ ^[0-9]+$ ]]; then
    printf '%s\n' "${value}"
    return 0
  fi
  if value="$(stat -f "${bsd_format}" "${path}" 2>/dev/null)" \
    && [[ "${value}" =~ ^[0-9]+$ ]]; then
    printf '%s\n' "${value}"
    return 0
  fi
  return 1
}

bifrost_directory_mtime() {
  bifrost_stat_number "$1" '%Y' '%m'
}

bifrost_directory_identity() {
  local path="$1"
  local device inode owner
  device="$(bifrost_stat_number "${path}" '%d' '%d')" || return 1
  inode="$(bifrost_stat_number "${path}" '%i' '%i')" || return 1
  owner="$(bifrost_stat_number "${path}" '%u' '%u')" || return 1
  printf '%s:%s:%s\n' "${device}" "${inode}" "${owner}"
}
