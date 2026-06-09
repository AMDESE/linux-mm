#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""
Parse one or two logs produced by bench-folio-copy.sh.

Single log: print per-(fn, scenario, direction) throughput table.
Two logs:   print a baseline-vs-optimized speedup table per cell.

Cells where stdev is at least 5% of the mean are flagged with '!' so
noisy rows are obvious without re-running.  Scenario / order cells
that the driver did not measure (e.g. order 0..5 in the cache-cold
1 GB scenario, where each iteration would take seconds of cache
flushing) are printed as "--" rather than silently dropped.

Usage:
    parse-folio-copy.py <baseline.log>
    parse-folio-copy.py <baseline.log> <optimized.log>
    parse-folio-copy.py                # uses the two newest logs in results/
"""

import glob
import os
import re
import statistics
import sys
from collections import defaultdict

RESULT_RE = re.compile(
    r"^RESULT\s+fn=(?P<fn>\S+)\s+order=(?P<order>\d+)\s+"
    r"src=(?P<src>\d+)\s+dst=(?P<dst>\d+)\s+pages=\S+\s+bytes=\S+\s+"
    r"iters=(?P<iters>\d+)\s+bytes_total=(?P<bytes_total>\d+)\s+"
    r"flush=(?P<flush>\d+)\s+warmup=(?P<warmup>\d+)"
    r"(?:\s+warmup_eff=(?P<warmup_eff>\d+))?\s+"
    r"total_ns=\S+\s+avg_ns=(?P<avg_ns>\d+)\s+"
    r"min_ns=\S+\s+max_ns=\S+\s+throughput_GBps=(?P<tput>[\d.]+)"
)
HEADER_RE = re.compile(r"^# release=(?P<release>\S+)")

# --- move_pages_bench log format ---
#   --- node 0 <-> 1 ---
#   iter= 0 -> node 1  9.658 GB/s  (16352/16384 pages on target)
MP_PAIR_RE = re.compile(r"^---\s+node\s+(?P<a>\d+)(?:\s+<->\s+(?P<b>\d+))?")
MP_ITER_RE = re.compile(
    r"^iter=\s*\d+\s+->\s+node\s+(?P<target>\d+)\s+(?P<gbps>[\d.]+)\s+GB/s")
MP_KERNEL_RE = re.compile(r"^#\s*kernel:\s*(?P<release>\S+)")


def pagesize_str(order):
    kb = 4 * (1 << order)
    if kb < 1024:
        return f"{kb}K"
    return f"{kb // 1024}M"


def bytes_str(n):
    for unit, step in [("G", 1 << 30), ("M", 1 << 20), ("K", 1 << 10)]:
        if n >= step and n % step == 0:
            return f"{n // step}{unit}"
    return f"{n}B"


def mean_std(xs):
    if not xs:
        return None, None
    mu = statistics.fmean(xs)
    sd = statistics.pstdev(xs) if len(xs) > 1 else 0.0
    return mu, sd


def load(path):
    """key -> list of tputs. Key is (fn, src, dst, bytes_total, flush, order)."""
    kernel = None
    data = defaultdict(list)
    with open(path) as f:
        for line in f:
            m = HEADER_RE.match(line)
            if m and not kernel:
                kernel = m["release"]
            mr = RESULT_RE.match(line.strip())
            if not mr:
                continue
            key = (mr["fn"], int(mr["src"]), int(mr["dst"]),
                   int(mr["bytes_total"]), int(mr["flush"]),
                   int(mr["order"]))
            data[key].append(float(mr["tput"]))
    return kernel or "(unknown)", data


def print_single(kernel, data):
    print(f"Kernel: {kernel}\n")
    # Group by (fn, src, dst, bytes_total, flush). Rows = order.
    groups = defaultdict(list)
    for key, vals in data.items():
        fn, src, dst, bt, fl, order = key
        groups[(fn, src, dst, bt, fl)].append((order, vals))

    for gk in sorted(groups.keys()):
        fn, src, dst, bt, fl = gk
        print(f"=== fn={fn} {src}->{dst} total={bytes_str(bt)} flush={fl} ===")
        print(f"  {'order':<6} {'pgsize':<8} {'tput (GB/s)':<24} {'n':<3}")
        print("  " + "-" * 50)
        for order, vals in sorted(groups[gk]):
            mu, sd = mean_std(vals)
            print(f"  {order:<6} {pagesize_str(order):<8} "
                  f"{mu:6.2f} +/- {sd:5.2f}         {len(vals)}")
        print()


def _fmt_cell(mu, sd, noisy_pct):
    """Render 'MU +/- SD' with a '!' marker when sd/mu > noisy_pct."""
    if mu is None:
        return f"{'--':>21}"
    rel = (sd / mu * 100.0) if mu else 0.0
    flag = "!" if rel >= noisy_pct else " "
    return f"{mu:7.2f} +/- {sd:5.2f}{flag}  "


def print_ab(ka, da, kb, db, noisy_pct=5.0):
    print(f"Baseline kernel:   {ka}")
    print(f"Optimized kernel:  {kb}")
    print(f"('!' flags rows where stdev >= {noisy_pct:.0f}% of mean)")
    print()

    # Keep every (fn, src, dst, bt, fl, order) seen in EITHER log so rows
    # that exist in only one run are still visible (no silent drops).
    keys = sorted(set(da.keys()) | set(db.keys()))
    if not keys:
        print("No data.")
        return

    # Also gather the set of orders per (fn, src, dst, bt, fl) scenario.
    groups = defaultdict(dict)  # scenario -> {order: (a_mu,a_sd,b_mu,b_sd)}
    all_orders_per_group = defaultdict(set)
    all_orders_seen = set()
    for k in keys:
        fn, src, dst, bt, fl, order = k
        all_orders_seen.add(order)
        all_orders_per_group[(fn, src, dst, bt, fl)].add(order)
        a_mu, a_sd = mean_std(da.get(k, []))
        b_mu, b_sd = mean_std(db.get(k, []))
        groups[(fn, src, dst, bt, fl)][order] = (a_mu, a_sd, b_mu, b_sd)

    # Use the union of all orders seen in the file as the row set so
    # scenario D's missing orders 0..5 print as '--' instead of silently
    # disappearing.
    order_row_set = sorted(all_orders_seen)

    for gk in sorted(groups.keys()):
        fn, src, dst, bt, fl = gk
        print(f"=== fn={fn} {src}->{dst} total={bytes_str(bt)} flush={fl} ===")
        print(f"  {'order':<6} {'pgsize':<8} "
              f"{'baseline GB/s':<23} "
              f"{'optimized GB/s':<23} "
              f"{'speedup':<10}")
        print("  " + "-" * 76)
        for order in order_row_set:
            cell = groups[gk].get(order)
            if cell is None:
                print(f"  {order:<6} {pagesize_str(order):<8} "
                      f"{'--':>21}  {'--':>21}  "
                      f"{'  n/a':<10}  (not measured in this scenario)")
                continue
            a_mu, a_sd, b_mu, b_sd = cell
            if a_mu and b_mu:
                ratio_str = f"{(b_mu / a_mu):.2f}x"
            elif b_mu:
                ratio_str = "  new  "
            elif a_mu:
                ratio_str = " gone  "
            else:
                ratio_str = "  n/a  "
            print(f"  {order:<6} {pagesize_str(order):<8} "
                  f"{_fmt_cell(a_mu, a_sd, noisy_pct)}"
                  f"{_fmt_cell(b_mu, b_sd, noisy_pct)}"
                  f"{ratio_str:<10}")
        print()


def is_move_pages_log(path):
    """True if the log looks like a move_pages_bench log, not a folio log."""
    with open(path) as f:
        for line in f:
            if RESULT_RE.match(line.strip()):
                return False
            if MP_ITER_RE.match(line.strip()):
                return True
    return False


def load_move_pages(path):
    """key -> list of GB/s. Key is (a, b, target) within each node pair."""
    kernel = None
    data = defaultdict(list)
    pair = (None, None)
    with open(path) as f:
        for line in f:
            line = line.strip()
            m = MP_KERNEL_RE.match(line)
            if m and not kernel:
                kernel = m["release"]
                continue
            mp = MP_PAIR_RE.match(line)
            if mp:
                a = int(mp["a"])
                b = int(mp["b"]) if mp["b"] is not None else a
                pair = (a, b)
                continue
            mi = MP_ITER_RE.match(line)
            if mi and pair[0] is not None:
                key = (pair[0], pair[1], int(mi["target"]))
                data[key].append(float(mi["gbps"]))
    return kernel or "(unknown)", data


def print_single_move_pages(kernel, data):
    print(f"Kernel: {kernel}\n")
    print(f"  {'pair':<10} {'-> node':<8} {'GB/s':<20} {'n':<3}")
    print("  " + "-" * 46)
    for key in sorted(data):
        a, b, target = key
        mu, sd = mean_std(data[key])
        print(f"  {a}<->{b:<6} {target:<8} {mu:7.2f} +/- {sd:5.2f}      "
              f"{len(data[key])}")
    print()


def print_ab_move_pages(ka, da, kb, db, noisy_pct=5.0):
    print(f"Baseline kernel:   {ka}")
    print(f"Optimized kernel:  {kb}")
    print(f"('!' flags rows where stdev >= {noisy_pct:.0f}% of mean)\n")

    keys = sorted(set(da) | set(db))
    if not keys:
        print("No move_pages data.")
        return

    print(f"  {'pair':<10} {'-> node':<8} "
          f"{'baseline GB/s':<23} {'optimized GB/s':<23} {'speedup':<10}")
    print("  " + "-" * 76)
    for key in keys:
        a, b, target = key
        a_mu, a_sd = mean_std(da.get(key, []))
        b_mu, b_sd = mean_std(db.get(key, []))
        if a_mu and b_mu:
            ratio = f"{(b_mu / a_mu):.2f}x"
        elif b_mu:
            ratio = "  new  "
        elif a_mu:
            ratio = " gone  "
        else:
            ratio = "  n/a  "
        print(f"  {a}<->{b:<6} {target:<8} "
              f"{_fmt_cell(a_mu, a_sd, noisy_pct)}"
              f"{_fmt_cell(b_mu, b_sd, noisy_pct)}"
              f"{ratio:<10}")
    print()


def main():
    args = sys.argv[1:]
    if not args:
        cands = sorted(glob.glob(os.path.join(
            os.path.dirname(__file__) or ".", "results", "ab_*.log")),
                       key=os.path.getmtime)
        if len(cands) >= 2:
            args = cands[-2:]
        elif len(cands) == 1:
            args = cands
        else:
            print("No results/ab_*.log found", file=sys.stderr)
            sys.exit(1)

    missing = [a for a in args if not os.path.isfile(a)]
    if missing:
        for m in missing:
            print(f"error: log not found: {m}", file=sys.stderr)
        print("\nGenerate logs first with:  sudo ./run.sh", file=sys.stderr)
        sys.exit(1)

    move_pages = is_move_pages_log(args[0])

    if len(args) == 1:
        print(f"Parsing: {args[0]}\n")
        if move_pages:
            kernel, data = load_move_pages(args[0])
            print_single_move_pages(kernel, data)
        else:
            kernel, data = load(args[0])
            print_single(kernel, data)
    else:
        print(f"Parsing baseline:  {args[0]}")
        print(f"Parsing optimized: {args[1]}\n")
        if move_pages:
            ka, da = load_move_pages(args[0])
            kb, db = load_move_pages(args[1])
            print_ab_move_pages(ka, da, kb, db)
        else:
            ka, da = load(args[0])
            kb, db = load(args[1])
            print_ab(ka, da, kb, db)


if __name__ == "__main__":
    main()
