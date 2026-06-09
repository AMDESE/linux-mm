# folio copy / migration benchmark kit

Standalone kit to measure the effect of batching `folio_copy()` /
`folio_mc_copy()` (used by page migration). Run it on a **baseline**
kernel and a **patched** kernel, then diff the logs.

## Contents

| File | What it is |
|------|------------|
| `folio_copy_ab_bench.c` | In-kernel A/B microbench module. Times `folio_copy()` / `folio_mc_copy()` on a src/dst folio pair across orders, NUMA directions, and cache-hot/cold regimes. debugfs at `/sys/kernel/debug/folio_copy_ab/`. |
| `bench-folio-copy.sh` | Driver for the module: sweeps 4 scenarios (2 MB / 1 GB × hot / cold) over orders and node pairs, with CPU pinning and repeats, logging to `results/`. |
| `parse-folio-copy.py` | Parses one log (table) or two logs (baseline-vs-patched speedup table, flags noisy rows). |
| `move_pages_bench.c` | Userspace end-to-end migration throughput via `move_pages(2)`, no libnuma. |
| `selftest.sh` | Loads the module and runs its in-kernel correctness selftest. |
| `run.sh` | One-shot: builds everything and runs both benchmarks across all online NUMA node pairs. |

## Build

    make            # builds folio_copy_ab_bench.ko and move_pages_bench

Needs the running kernel's build tree (`/lib/modules/$(uname -r)/build`).
Override with `make KDIR=/path/to/build`.

## One-shot run

    sudo ./run.sh

    # bigger / longer:
    sudo ORDERS="0 4 8 9" REPEATS=10 SIZE_MB=1024 ITERS=10 ./run.sh

This builds, runs the folio A/B sweep (log under `results/ab_*.log`), then
the `move_pages(2)` bench (log under `results/move_pages-*.log`).

Run it on the baseline kernel, reboot into the patched kernel, run it
again, then compare the two folio logs:

    ./parse-folio-copy.py results/ab_<baseline>.log results/ab_<patched>.log

## Correctness check

    sudo ./selftest.sh      # verifies folio copies before perf measurement

## Manual / individual use

In-kernel bench knobs (`/sys/kernel/debug/folio_copy_ab/`): `order`,
`src_node`, `dst_node`, `bytes_total`, `flush` (1=cold, 0=hot), `warmup`,
`max_iters`, `copy_fn` (0=mc, 1=plain, 2=both). Read `run` to execute.

    sudo ./move_pages_bench 1024 0 1 10   # 1 GiB, node 0<->1, 10 iters

## Notes

- `run.sh` leaves the module loaded so it is re-runnable; `sudo rmmod
  folio_copy_ab_bench` to unload.
- `order` is in base pages: order 9 = 2 MiB on 4 KiB-base systems but
  32 MiB on 64 KiB-base systems (e.g. some arm64 configs). On 64 KiB-base
  kernels pass smaller `ORDERS` (e.g. `ORDERS="0 2 4 5"` for up to 2 MiB).
- On arm64, `copy_highpage()` is overridden for MTE, so a vanilla kernel
  takes the per-page path; the bench still reports baseline throughput.
- To exercise large folios in `move_pages_bench`, enable THP:
  `echo always > /sys/kernel/mm/transparent_hugepage/enabled`.
