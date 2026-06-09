#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Quick correctness check before perf measurement.
#
# Loads the folio_copy_ab_bench module and runs its in-kernel
# selftest (which calls folio_mc_copy() and folio_copy() on a small
# set of orders and verifies that dst contains the same bytes as src).
# Use this on both the baseline and patched kernel to confirm neither
# has corrupted the copy primitives before running the bench.
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DBG=/sys/kernel/debug/folio_copy_ab

if [[ $EUID -ne 0 ]]; then
    echo "Run as root." >&2
    exit 1
fi

mount | grep -q '^debugfs ' || mount -t debugfs none /sys/kernel/debug

if [[ ! -d ${DBG} ]]; then
    if ! modprobe folio_copy_ab_bench 2>/dev/null; then
        for ko in "${SCRIPT_DIR}/folio_copy_ab_bench.ko" \
                  "${SCRIPT_DIR}/../bench-module/folio_copy_ab_bench.ko"; do
            if [[ -f ${ko} ]] && insmod "${ko}" 2>/dev/null; then
                break
            fi
        done
    fi
fi

[[ -e ${DBG}/selftest ]] || {
    echo "${DBG}/selftest missing.  Build the module in this directory first:" >&2
    echo "    cd ${SCRIPT_DIR} && make" >&2
    exit 1
}

cat "${DBG}/selftest"
