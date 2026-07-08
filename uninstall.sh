#!/usr/bin/env bash
# =============================================================================
# Thin wrapper that calls install.sh --uninstall.
# Exists so people who reach for `uninstall.sh` find it.
#
# `exec` REPLACES this shell process with install.sh (rather than running it
# as a child), so exit codes and signals pass straight through. "$@" forwards
# any extra arguments the user supplied.
# =============================================================================

set -Eeuo pipefail

# Directory this script lives in — lets it be run from anywhere.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "${SCRIPT_DIR}/install.sh" --uninstall "$@"
