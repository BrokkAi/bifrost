#!/usr/bin/env bash
set -u

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/bifrost-tmp.sh
source "${script_dir}/lib/bifrost-tmp.sh"

usage() {
  cat >&2 <<'EOF'
Usage: scripts/cleanup-bifrost-tmp.sh [--apply] [--include-unmanaged] [--older-than-hours N] [--tmp-root PATH]

Lists stale, inactive bifrost-* temporary directories. The default is a dry run;
pass --apply to remove eligible helper-managed directories. Existing unmarked
directories require both --apply and --include-unmanaged.
EOF
}

apply=0
include_unmanaged=0
older_than_hours=24
tmp_root="$(bifrost_tmp_root)"
maximum_age_hours=876000

while [ "$#" -gt 0 ]; do
  case "$1" in
    --apply)
      apply=1
      shift
      ;;
    --include-unmanaged)
      include_unmanaged=1
      shift
      ;;
    --older-than-hours)
      if [ "$#" -lt 2 ]; then
        echo "--older-than-hours requires a value" >&2
        exit 2
      fi
      older_than_hours="$2"
      shift 2
      ;;
    --tmp-root)
      if [ "$#" -lt 2 ]; then
        echo "--tmp-root requires a value" >&2
        exit 2
      fi
      tmp_root="$2"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

case "${older_than_hours}" in
  ''|*[!0-9]*)
    echo "--older-than-hours expects a non-negative integer" >&2
    exit 2
    ;;
esac

shopt -s extglob
normalized_age_hours="${older_than_hours##+(0)}"
normalized_age_hours="${normalized_age_hours:-0}"
if [ "${#normalized_age_hours}" -gt "${#maximum_age_hours}" ] \
  || { [ "${#normalized_age_hours}" -eq "${#maximum_age_hours}" ] \
    && [[ "${normalized_age_hours}" > "${maximum_age_hours}" ]]; }; then
  echo "--older-than-hours must not exceed ${maximum_age_hours}" >&2
  exit 2
fi
older_than_hours="${normalized_age_hours}"

bifrost_require_tmp_root "${tmp_root}" || exit 1

now="$(date +%s)"
minimum_age_seconds=$((older_than_hours * 60 * 60))
activity_probe_available=0
current_uid="$(id -u)"
result=0
if command -v lsof >/dev/null 2>&1; then
  activity_probe_available=1
fi

directory_activity() {
  local output status
  output="$(lsof -Fn +D "$1" 2>/dev/null)"
  status=$?
  if [ -n "${output}" ]; then
    return 0
  fi
  if [ "${status}" -eq 1 ]; then
    return 1
  fi
  return 2
}

shopt -s nullglob
for candidate in "${tmp_root%/}"/bifrost-*; do
  if [ ! -d "${candidate}" ] || [ -L "${candidate}" ]; then
    continue
  fi

  if [ -e "${candidate}/.bifrost-keep" ]; then
    echo "Skip retained: ${candidate}"
    continue
  fi

  basename_candidate="$(basename "${candidate}")"
  managed_version=""
  managed_uid=""
  managed_name=""
  if [ -f "${candidate}/.bifrost-managed-target" ]; then
    while IFS='=' read -r key value; do
      case "${key}" in
        version) managed_version="${value}" ;;
        uid) managed_uid="${value}" ;;
        name) managed_name="${value}" ;;
      esac
    done < "${candidate}/.bifrost-managed-target"
  fi
  managed=0
  case "${basename_candidate}" in
    bifrost-cargo-target.*)
      if [ "${managed_version}" = "1" ] \
        && [ "${managed_uid}" = "${current_uid}" ] \
        && [ "${managed_name}" = "${basename_candidate}" ]; then
        managed=1
      fi
      ;;
  esac
  if [ "${managed}" -ne 1 ] && [ "${include_unmanaged}" -ne 1 ]; then
    echo "Skip unmanaged (use --include-unmanaged after review): ${candidate}"
    continue
  fi

  checked_identity="$(bifrost_directory_identity "${candidate}")" || {
    echo "Skip unreadable identity: ${candidate}" >&2
    continue
  }
  checked_owner="${checked_identity##*:}"
  if [ "${checked_owner}" != "${current_uid}" ]; then
    echo "Skip directory owned by UID ${checked_owner}: ${candidate}"
    continue
  fi

  active_pid=""
  if [ -f "${candidate}/.bifrost-active-pid" ]; then
    while IFS= read -r marker_pid; do
      case "${marker_pid}" in
        ''|*[!0-9]*) ;;
        *)
          if kill -0 "${marker_pid}" 2>/dev/null; then
            active_pid="${marker_pid}"
            break
          fi
          ;;
      esac
    done < "${candidate}/.bifrost-active-pid"
  fi
  if [ -n "${active_pid}" ]; then
    echo "Skip active PID ${active_pid}: ${candidate}"
    continue
  fi

  modified_at="$(bifrost_directory_mtime "${candidate}")" || {
    echo "Skip unreadable timestamp: ${candidate}" >&2
    continue
  }
  age_seconds=$((now - modified_at))
  if [ "${age_seconds}" -lt "${minimum_age_seconds}" ]; then
    echo "Skip newer than ${older_than_hours}h: ${candidate}"
    continue
  fi

  if [ "${activity_probe_available}" -ne 1 ]; then
    echo "Skip; lsof is required to prove inactivity: ${candidate}" >&2
    continue
  fi
  if directory_activity "${candidate}"; then
    echo "Skip open directory: ${candidate}"
    continue
  else
    activity_status=$?
    if [ "${activity_status}" -ne 1 ]; then
      echo "Skip; lsof could not inspect directory: ${candidate}" >&2
      continue
    fi
  fi

  if [ "${apply}" -ne 1 ]; then
    echo "Would remove: ${candidate}"
    continue
  fi

  current_identity="$(bifrost_directory_identity "${candidate}")" || {
    echo "Skip vanished candidate: ${candidate}" >&2
    continue
  }
  if [ "${current_identity}" != "${checked_identity}" ]; then
    echo "Skip replaced candidate: ${candidate}" >&2
    continue
  fi

  quarantine="${tmp_root%/}/.bifrost-cleanup-quarantine.$$.$RANDOM.${basename_candidate}"
  if ! mv "${candidate}" "${quarantine}"; then
    echo "Failed to quarantine: ${candidate}" >&2
    result=1
    continue
  fi
  quarantine_identity="$(bifrost_directory_identity "${quarantine}")" || true
  if [ "${quarantine_identity}" != "${checked_identity}" ]; then
    echo "Refusing to delete replaced candidate now at: ${quarantine}" >&2
    if [ ! -e "${candidate}" ]; then
      mv "${quarantine}" "${candidate}" 2>/dev/null || true
    fi
    result=1
    continue
  fi
  if directory_activity "${quarantine}"; then
    echo "Refusing to delete directory that became active: ${quarantine}" >&2
    if [ ! -e "${candidate}" ]; then
      mv "${quarantine}" "${candidate}" 2>/dev/null || true
    fi
    result=1
    continue
  else
    activity_status=$?
    if [ "${activity_status}" -ne 1 ]; then
      echo "Refusing to delete directory that could not be re-inspected: ${quarantine}" >&2
      if [ ! -e "${candidate}" ]; then
        mv "${quarantine}" "${candidate}" 2>/dev/null || true
      fi
      result=1
      continue
    fi
  fi

  if rm -rf "${quarantine}" && [ ! -e "${quarantine}" ]; then
    echo "Removed: ${candidate}"
  else
    failed_path="${quarantine}"
    if [ -e "${quarantine}" ] && [ ! -e "${candidate}" ] \
      && mv "${quarantine}" "${candidate}" 2>/dev/null; then
      failed_path="${candidate}"
    fi
    echo "Failed to remove directory; remaining data is at: ${failed_path}" >&2
    result=1
  fi
done

exit "${result}"
