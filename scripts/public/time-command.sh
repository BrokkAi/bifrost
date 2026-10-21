#!/usr/bin/env bash

# Run a command and report its peak memory and CPU time on exit.
#
# Public CI records the resource use of its compile-heavy steps to size its
# runners. GNU time spells that report `-v`, BSD time `-l`; this picks the
# host's spelling, so the same workflow step also runs in a local release dry
# run on macOS.
#
# Usage: scripts/public/time-command.sh <command> [args...]

set -euo pipefail

[[ $# -gt 0 ]] || { echo "usage: $0 COMMAND [ARGS...]" >&2; exit 2; }
case "$(uname -s)" in
  Linux) exec /usr/bin/time -v "$@" ;;
  Darwin) exec /usr/bin/time -l "$@" ;;
  *) exec "$@" ;;
esac
