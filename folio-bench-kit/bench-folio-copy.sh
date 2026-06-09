#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Driver for the folio_copy_ab_bench kernel module.  Sweeps a set of
# folio orders across a set of (src_node, dst_node) NUMA pairs in four
# scenarios:
#
#   A: total=2MB, cache-hot   (warmup auto-scaled inside the module)
#   B: total=2MB, cache-cold  (cache flushed before every iteration,
#                              capped at 8 timed iters at order 0 to
#                              keep run-time bounded)
#   C: total=1GB, cache-hot   (amortise per-iter overhead)
#   D: total=1GB, cache-cold  (orders >= 6 only, otherwise flush
#                              cost dominates)
#
# Each scenario / order / direction cell is repeated REPEATS times.
# All output is written to a single log under results/, tagged with
# the running kernel's release so A/B logs are trivially paired up
# afterwards by parse-folio-copy.py.
#
# Usage:
#   sudo ./bench-folio-copy.sh
#
# Environment overrides:
#   ORDERS="0 4 8 9"               folio orders to sweep
#   DIRECTIONS="0:0 0:1 0:2 2:0"   src:dst NUMA pairs
#   REPEATS=10                     reps per cell
#   PIN_CPU=auto                   "auto" -> first CPU on src node;
#                                  or a specific CPU id (e.g. 4)
#

set -euo pipefail

DBG=/sys/kernel/debug/folio_copy_ab
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="${SCRIPT_DIR}/results"
TS=$(date +%Y%m%d_%H%M%S)

if [[ $EUID -ne 0 ]]; then
    echo "Run as root." >&2
    exit 1
fi

mkdir -p "${LOG_DIR}"
mount | grep -q '^debugfs ' || mount -t debugfs none /sys/kernel/debug

# Try to make sure the bench module is loaded.  Look for it in common
# places: an in-tree install (modprobe), the local out-of-tree build
# in this directory, and a sibling linux/mm/ build.  Whichever matches
# the running kernel's vermagic wins.
if [[ ! -d ${DBG} ]]; then
    candidates=(
        "${SCRIPT_DIR}/folio_copy_ab_bench.ko"
        "${SCRIPT_DIR}/../bench-module/folio_copy_ab_bench.ko"
    )
    if ! modprobe folio_copy_ab_bench 2>/dev/null; then
        loaded=0
        for ko in "${candidates[@]}"; do
            if [[ -f ${ko} ]] && insmod "${ko}" 2>/dev/null; then
                loaded=1
                break
            fi
        done
        if [[ ${loaded} -eq 0 ]]; then
            cat >&2 <<ERR
Cannot load folio_copy_ab_bench.  Build it against the booted kernel:

    cd ${SCRIPT_DIR}
    make             # produces folio_copy_ab_bench.ko for $(uname -r)

Then re-run this script.
ERR
            exit 1
        fi
    fi
fi
[[ -d ${DBG} ]] || { echo "${DBG} still missing" >&2; exit 1; }

# Tag the log with a filename-friendly form of the kernel release so
# A/B logs are obvious on disk.
REL=$(awk -F= '$1=="release" {print $2}' "${DBG}/kernel" 2>/dev/null || uname -r)
REL_TAG=$(printf %s "${REL}" | tr -c '[:alnum:].-' _)
LOG="${LOG_DIR}/ab_${REL_TAG}_${TS}.log"

ORDERS=${ORDERS:-"0 2 4 6 7 8 9"}
DIRECTIONS=${DIRECTIONS:-"0:0 0:1 0:2 2:0"}
REPEATS=${REPEATS:-10}
PIN_CPU=${PIN_CPU:-auto}

# Return the first CPU id on node $1, or 0 if that node has no CPUs
# (e.g. CXL.mem nodes).  The "first CPU on the source node" is the
# closest possible bench thread to where the source folio lives.
src_cpu_for_node() {
    local node=$1
    local cpulist
    cpulist=$(cat "/sys/devices/system/node/node${node}/cpulist" 2>/dev/null || true)
    if [[ -z "${cpulist}" ]]; then
        cpulist=$(cat /sys/devices/system/node/node0/cpulist 2>/dev/null || echo 0)
    fi
    local first=${cpulist%%[,-]*}
    echo "${first:-0}"
}

# Scenario format:  id:bytes_total:flush:warmup:max_iters:min_order
SCENARIOS=(
    "A:2097152:0:1:0:0"             # cache-hot 2MB
    "B:2097152:1:1:8:0"             # cache-cold 2MB (cap flushed iters)
    "C:1073741824:0:1:0:0"          # amortised 1GB no flush
    "D:1073741824:1:1:32:6"         # amortised 1GB flushed (orders >= 6)
)

{
    echo "# folio_copy A/B bench log"
    echo "# timestamp: ${TS}"
    echo "# host uname -a: $(uname -a)"
    echo "# --- kernel (from module /sys/kernel/debug/folio_copy_ab/kernel) ---"
    sed 's/^/# /' "${DBG}/kernel"
    echo "# --- cmdline ---"
    sed 's/^/# /' /proc/cmdline
    echo "# --- config flags (best-effort, /boot/config may be absent) ---"
    for k in CONFIG_PREEMPT_DYNAMIC CONFIG_PREEMPT \
             CONFIG_INIT_ON_ALLOC_DEFAULT_ON \
             CONFIG_HAVE_GIGANTIC_FOLIOS CONFIG_SPARSEMEM_VMEMMAP; do
        v=$(grep -E "^${k}=|^# ${k} is not set" "/boot/config-$(uname -r)" 2>/dev/null \
             || echo "${k}=?")
        echo "# ${v}"
    done
    echo "# --- topology (best-effort) ---"
    if command -v numactl >/dev/null 2>&1; then
        numactl -H 2>/dev/null | sed 's/^/# /'
    else
        echo "# numactl not available; recording per-node cpulist instead"
        for nd in /sys/devices/system/node/node[0-9]*; do
            n=${nd##*/node}
            echo "# node${n} cpus: $(cat "${nd}/cpulist" 2>/dev/null || echo '?')"
        done
    fi
    echo "# --- parameters ---"
    echo "# orders: ${ORDERS}"
    echo "# directions: ${DIRECTIONS}"
    echo "# repeats: ${REPEATS}"
    echo "# pin_cpu: ${PIN_CPU}"
    for s in "${SCENARIOS[@]}"; do echo "# scenario ${s}"; done
} | tee "${LOG}"

run_cell() {
    local scen=$1 bytes=$2 flush=$3 warmup=$4 max_iters=$5 \
          order=$6 src=$7 dst=$8 rep=$9
    local pin_cpu

    if [[ "${PIN_CPU}" == "auto" ]]; then
        pin_cpu=$(src_cpu_for_node "${src}")
    else
        pin_cpu=${PIN_CPU}
    fi

    echo "${order}"     > "${DBG}/order"
    echo "${src}"       > "${DBG}/src_node"
    echo "${dst}"       > "${DBG}/dst_node"
    echo "${bytes}"     > "${DBG}/bytes_total"
    echo "${flush}"     > "${DBG}/flush"
    echo "${warmup}"    > "${DBG}/warmup"
    echo "${max_iters}" > "${DBG}/max_iters"
    echo 2              > "${DBG}/copy_fn"   # 2 = both folio_mc_copy + folio_copy

    echo "# run scen=${scen} order=${order} src=${src} dst=${dst}" \
         "bytes_total=${bytes} flush=${flush} warmup=${warmup}" \
         "max_iters=${max_iters} pin_cpu=${pin_cpu} rep=${rep}" | tee -a "${LOG}"
    taskset -c "${pin_cpu}" cat "${DBG}/run" | tee -a "${LOG}"
}

for order in ${ORDERS}; do
    for dir_pair in ${DIRECTIONS}; do
        src=${dir_pair%:*}
        dst=${dir_pair#*:}

        for scen_def in "${SCENARIOS[@]}"; do
            IFS=: read -r id bytes flush warmup max_iters min_order \
                <<< "${scen_def}"
            if [[ ${order} -lt ${min_order} ]]; then
                continue
            fi
            for rep in $(seq 1 "${REPEATS}"); do
                run_cell "${id}" "${bytes}" "${flush}" "${warmup}" \
                         "${max_iters}" "${order}" "${src}" "${dst}" \
                         "${rep}"
            done
        done
    done
done

echo
echo "=== log: ${LOG} ==="
python3 "${SCRIPT_DIR}/parse-folio-copy.py" "${LOG}"
