#!/usr/bin/env bash

# Shared failure helper for the workflow shell entry points.
#
# `set -e` is not enough on its own: bash 3.2, which is what macOS ships and
# what a developer running these tests locally therefore uses, does not abort on
# a failed bare `[[ ]]`. An assertion written as `[[ ... ]] || die "..."` fails
# the same way everywhere, and says why -- a bare assertion that trips inside a
# workflow prints nothing but the step's exit code.

# Emit a GitHub Actions error annotation and stop. Outside Actions the ::error::
# prefix is inert, so the message reads the same in a terminal.
die() {
  echo "::error::$*" >&2
  exit 1
}
