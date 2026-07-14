#!/usr/bin/env bash
set -u

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/bifrost-tmp.sh
source "${script_dir}/lib/bifrost-tmp.sh"

usage() {
  echo "Usage: scripts/with-isolated-cargo-target.sh COMMAND [ARG ...]" >&2
}

if [ "$#" -eq 0 ]; then
  usage
  exit 2
fi

tmp_root="$(bifrost_tmp_root)"
bifrost_require_tmp_root "${tmp_root}" || exit 1

target_dir="$(mktemp -d "${tmp_root%/}/bifrost-cargo-target.XXXXXX")" || exit 1
active_marker="${target_dir}/.bifrost-active-pid"
keep_marker="${target_dir}/.bifrost-keep"
managed_marker="${target_dir}/.bifrost-managed-target"
target_name="$(basename "${target_dir}")"
current_uid="$(id -u)"
printf 'version=1\nuid=%s\nname=%s\n' "${current_uid}" "${target_name}" > "${managed_marker}"
printf '%s\n' "$$" > "${active_marker}"
export CARGO_TARGET_DIR="${target_dir}"

child_pid=""
process_group=""
cleanup_safe=1
signal_grace_seconds=2

process_group_active() {
  [ -n "${process_group}" ] && kill -0 -- "-${process_group}" 2>/dev/null
}

discover_child_process_group() {
  if [ -z "${child_pid}" ]; then
    for job_pid in $(jobs -pr); do
      child_pid="${job_pid}"
      break
    done
  fi
  if [ -n "${child_pid}" ] && [ -z "${process_group}" ]; then
    process_group="$(ps -o pgid= -p "${child_pid}" 2>/dev/null | tr -d ' ')"
    process_group="${process_group:-${child_pid}}"
  fi
}

stop_process_group() {
  signal="$1"
  discover_child_process_group
  if ! process_group_active; then
    [ -z "${child_pid}" ] || wait "${child_pid}" 2>/dev/null || true
    return 0
  fi

  kill -s "${signal}" -- "-${process_group}" 2>/dev/null || true
  deadline=$((SECONDS + signal_grace_seconds))
  while process_group_active && [ "${SECONDS}" -lt "${deadline}" ]; do
    sleep 0.1
  done
  if process_group_active; then
    kill -KILL -- "-${process_group}" 2>/dev/null || true
  fi
  [ -z "${child_pid}" ] || wait "${child_pid}" 2>/dev/null || true

  deadline=$((SECONDS + signal_grace_seconds))
  while process_group_active && [ "${SECONDS}" -lt "${deadline}" ]; do
    sleep 0.1
  done
  ! process_group_active
}

cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  if [ "${cleanup_safe}" -ne 1 ]; then
    : > "${keep_marker}"
    echo "Retained isolated Cargo target because its process group is still active: ${target_dir}" >&2
    [ "${status}" -ne 0 ] || status=1
  elif [ "${BIFROST_KEEP_TARGET:-0}" = "1" ]; then
    if ! rm -f "${active_marker}"; then
      echo "Failed to clear active marker: ${active_marker}" >&2
      [ "${status}" -ne 0 ] || status=1
    fi
    : > "${keep_marker}"
    echo "Retained isolated Cargo target: ${target_dir}" >&2
  else
    if rm -rf "${target_dir}" && [ ! -e "${target_dir}" ]; then
      echo "Removed isolated Cargo target: ${target_dir}" >&2
    else
      echo "Failed to remove isolated Cargo target: ${target_dir}" >&2
      [ "${status}" -ne 0 ] || status=1
    fi
  fi
  exit "${status}"
}

forward_signal() {
  signal="$1"
  status="$2"
  trap - "${signal}"
  shutdown_signal="${signal}"
  if [ "${signal}" = "INT" ]; then
    shutdown_signal=TERM
  fi
  if ! stop_process_group "${shutdown_signal}"; then
    cleanup_safe=0
  fi
  exit "${status}"
}

trap cleanup EXIT
trap 'forward_signal HUP 129' HUP
trap 'forward_signal INT 130' INT
trap 'forward_signal TERM 143' TERM

echo "Using isolated Cargo target: ${target_dir}" >&2
set -m
"$@" &
child_pid=$!
process_group="$(ps -o pgid= -p "${child_pid}" 2>/dev/null | tr -d ' ')"
process_group="${process_group:-${child_pid}}"
set +m
printf '%s\n%s\n' "$$" "${child_pid}" > "${active_marker}"
wait "${child_pid}"
status=$?
if process_group_active && ! stop_process_group TERM; then
  cleanup_safe=0
fi
exit "${status}"
