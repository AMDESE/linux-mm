#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# One-shot standalone driver for the folio copy / migration bench kit.
#
# Builds everything, then runs:
#   1. folio_copy() / folio_mc_copy() A/B microbench (bench-folio-copy.sh)
#   2. move_pages(2) end-to-end migration bench (move_pages_bench)
#
# Run it once on the BASELINE kernel and once on the PATCHED kernel, then
# diff the two folio-bench logs with parse-folio-copy.py.
#
#   sudo ./run.sh
#   sudo ORDERS="0 4 8 9" REPEATS=5 SIZE_MB=1024 ITERS=10 ./run.sh
#
# Env knobs:
#   ORDERS      folio orders for the in-kernel sweep   (default "0 4 8 9")
#   REPEATS     reps per cell                          (default 5)
#   SIZE_MB     move_pages region size in MiB          (default 512)
#   ITERS       move_pages iterations per node pair    (default 6)
#   KDIR        kernel build dir                       (default running kernel)

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

SIZE_MB="${SIZE_MB:-512}"
ITERS="${ITERS:-6}"
RESULTS="$HERE/results"
TS="$(date +%Y%m%d-%H%M%S)"

die() { echo "FATAL: $*" >&2; exit 1; }
[[ $(id -u) -eq 0 ]] || die "run as root (sudo ./run.sh)"

mkdir -p "$RESULTS"

# Online NUMA nodes as a space-separated list, e.g. "0 1".
NODES=$(for d in /sys/devices/system/node/node[0-9]*; do
		basename "$d" | sed 's/node//'; done | sort -n | tr '\n' ' ')
NODES="${NODES% }"
[[ -n "$NODES" ]] || NODES=0

# Build folio_copy_ab_bench.ko + move_pages_bench.
echo "=== build ==="
make all ${KDIR:+KDIR="$KDIR"} || die "build failed"

# All (src:dst) node pairs for the in-kernel sweep.
DIRS=""
for s in $NODES; do
	for d in $NODES; do
		DIRS="$DIRS $s:$d"
	done
done
DIRS="${DIRS# }"

# 1. In-kernel folio_copy/folio_mc_copy A/B sweep. bench-folio-copy.sh
#    loads the module, sweeps scenarios/orders/directions, writes a log
#    under results/, and prints a single-log table at the end.
echo
echo "=== folio_copy_ab_bench sweep ==="
ORDERS="${ORDERS:-0 4 8 9}" \
REPEATS="${REPEATS:-5}" \
DIRECTIONS="$DIRS" \
	./bench-folio-copy.sh || die "folio bench failed"

# 2. move_pages(2) end-to-end, every distinct node pair.
MPLOG="$RESULTS/move_pages-$TS.log"
echo
echo "=== move_pages_bench ===" | tee "$MPLOG"
{
	echo "# kernel: $(uname -r)"
	echo "# SIZE_MB=$SIZE_MB ITERS=$ITERS nodes=$NODES"
} | tee -a "$MPLOG"
ran_mp=0
for a in $NODES; do
	for b in $NODES; do
		[[ "$a" -lt "$b" ]] || continue
		echo "--- node $a <-> $b ---" | tee -a "$MPLOG"
		./move_pages_bench "$SIZE_MB" "$a" "$b" "$ITERS" | tee -a "$MPLOG"
		ran_mp=1
	done
done
if [[ "$ran_mp" -eq 0 ]]; then
	echo "--- node $NODES (single-node) ---" | tee -a "$MPLOG"
	./move_pages_bench "$SIZE_MB" "$NODES" "$NODES" "$ITERS" | tee -a "$MPLOG"
fi

echo
echo "Done."
echo "  folio logs:      $RESULTS/ab_*.log"
echo "  move_pages log:  $MPLOG"
echo
echo "To compare baseline vs patched folio runs:"
echo "  ./parse-folio-copy.py <baseline_ab.log> <patched_ab.log>"
