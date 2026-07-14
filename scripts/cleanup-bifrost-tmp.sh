#!/usr/bin/env bash
set -u

usage() {
  cat >&2 <<'EOF'
Usage: scripts/cleanup-bifrost-tmp.sh [--apply] [--older-than-hours N] [--tmp-root PATH]

Lists stale, inactive bifrost-* temporary directories. The default is a dry run;
pass --apply to remove eligible directories.
EOF
}

apply=0
older_than_hours=24
if [ -n "${BIFROST_TMP_ROOT:-}" ]; then
  tmp_root="${BIFROST_TMP_ROOT}"
elif [ -d /private/tmp ]; then
  tmp_root=/private/tmp
else
  tmp_root="${TMPDIR:-/tmp}"
fi

while [ "$#" -gt 0 ]; do
  case "$1" in
    --apply)
      apply=1
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

if [ ! -d "${tmp_root}" ]; then
  echo "Temporary root does not exist: ${tmp_root}" >&2
  exit 1
fi

directory_mtime() {
  if stat -f '%m' "$1" 2>/dev/null; then
    return 0
  fi
  stat -c '%Y' "$1" 2>/dev/null
}

now="$(date +%s)"
minimum_age_seconds=$((older_than_hours * 60 * 60))
activity_probe_available=0
if command -v lsof >/dev/null 2>&1; then
  activity_probe_available=1
fi

shopt -s nullglob
for candidate in "${tmp_root%/}"/bifrost-*; do
  if [ ! -d "${candidate}" ] || [ -L "${candidate}" ]; then
    continue
  fi

  if [ -e "${candidate}/.bifrost-keep" ]; then
    echo "Skip retained: ${candidate}"
    continue
  fi

  active_pid=""
  if [ -f "${candidate}/.bifrost-active-pid" ]; then
    IFS= read -r active_pid < "${candidate}/.bifrost-active-pid" || true
  fi
  case "${active_pid}" in
    ''|*[!0-9]*) ;;
    *)
      if kill -0 "${active_pid}" 2>/dev/null; then
        echo "Skip active PID ${active_pid}: ${candidate}"
        continue
      fi
      ;;
  esac

  modified_at="$(directory_mtime "${candidate}")" || {
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
  if lsof +D "${candidate}" >/dev/null 2>&1; then
    echo "Skip open directory: ${candidate}"
    continue
  else
    lsof_status=$?
    if [ "${lsof_status}" -ne 1 ]; then
      echo "Skip; lsof could not inspect directory: ${candidate}" >&2
      continue
    fi
  fi

  if [ "${apply}" -eq 1 ]; then
    rm -rf "${candidate}"
    echo "Removed: ${candidate}"
  else
    echo "Would remove: ${candidate}"
  fi
done
