#!/usr/bin/env bash
set -u

usage() {
  echo "Usage: scripts/with-isolated-cargo-target.sh COMMAND [ARG ...]" >&2
}

if [ "$#" -eq 0 ]; then
  usage
  exit 2
fi

if [ -n "${BIFROST_TMP_ROOT:-}" ]; then
  tmp_root="${BIFROST_TMP_ROOT}"
elif [ -d /private/tmp ]; then
  tmp_root=/private/tmp
else
  tmp_root="${TMPDIR:-/tmp}"
fi
if [ ! -d "${tmp_root}" ]; then
  echo "Temporary root does not exist: ${tmp_root}" >&2
  exit 1
fi

target_dir="$(mktemp -d "${tmp_root%/}/bifrost-cargo-target.XXXXXX")" || exit 1
active_marker="${target_dir}/.bifrost-active-pid"
keep_marker="${target_dir}/.bifrost-keep"
printf '%s\n' "$$" > "${active_marker}"
export CARGO_TARGET_DIR="${target_dir}"

child_pid=""

cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  if [ "${BIFROST_KEEP_TARGET:-0}" = "1" ]; then
    rm -f "${active_marker}"
    : > "${keep_marker}"
    echo "Retained isolated Cargo target: ${target_dir}" >&2
  else
    rm -rf "${target_dir}"
    echo "Removed isolated Cargo target: ${target_dir}" >&2
  fi
  exit "${status}"
}

forward_signal() {
  signal="$1"
  status="$2"
  trap - "${signal}"
  if [ -z "${child_pid}" ]; then
    for job_pid in $(jobs -pr); do
      child_pid="${job_pid}"
      break
    done
  fi
  if [ -n "${child_pid}" ] && kill -0 "${child_pid}" 2>/dev/null; then
    kill -s "${signal}" "${child_pid}" 2>/dev/null || true
    wait "${child_pid}" 2>/dev/null || true
  fi
  exit "${status}"
}

trap cleanup EXIT
trap 'forward_signal HUP 129' HUP
trap 'forward_signal INT 130' INT
trap 'forward_signal TERM 143' TERM

echo "Using isolated Cargo target: ${target_dir}" >&2
"$@" &
child_pid=$!
printf '%s\n%s\n' "$$" "${child_pid}" > "${active_marker}"
wait "${child_pid}"
status=$?
child_pid=""
exit "${status}"
